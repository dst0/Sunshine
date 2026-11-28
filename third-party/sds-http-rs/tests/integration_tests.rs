use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::crypto::{aws_lc_rs, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sds_http_rs::client::{ClientSettings, HttpClientInstance};
use sds_http_rs::server::{
    ErrorKind, HttpServerInstance, ResponseSenderHandle, ServerCallbacks, ServerRequestHeadFfi,
    ServerSettings,
};
use std::ffi::c_void;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("sds_http_rs_{name}_{}_{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct TempCertPair {
    _dir: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn generate_cert(name: &str, cn: &str) -> TempCertPair {
    let dir = temp_dir(name);
    let cert = generate_simple_self_signed(vec![cn.to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();
    TempCertPair {
        _dir: dir,
        cert_path,
        key_path,
        cert_der: cert.cert.der().to_vec(),
        key_der: cert.key_pair.serialize_der(),
    }
}

#[derive(Debug)]
struct AcceptAllServerCerts {
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAllServerCerts {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

struct TestServerState {
    bound_port: Mutex<Option<u16>>,
    live_connections: AtomicUsize,
    live_requests: AtomicUsize,
    dispatched_count: AtomicUsize,
    verify_called: AtomicUsize,
    verify_failed_called: AtomicUsize,
    errors: Mutex<Vec<ErrorKind>>,
    allow_client_verify: AtomicBool,
    reject_header_if_body_gt: AtomicUsize,
    delay_response_ms: AtomicUsize,
    abort_response: AtomicBool,
    close_after_response: AtomicBool,
    emit_keep_alive_header: AtomicBool,
    expected_client_der: Mutex<Option<Vec<u8>>>,
}

impl TestServerState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            bound_port: Mutex::new(None),
            live_connections: AtomicUsize::new(0),
            live_requests: AtomicUsize::new(0),
            dispatched_count: AtomicUsize::new(0),
            verify_called: AtomicUsize::new(0),
            verify_failed_called: AtomicUsize::new(0),
            errors: Mutex::new(Vec::new()),
            allow_client_verify: AtomicBool::new(true),
            reject_header_if_body_gt: AtomicUsize::new(usize::MAX),
            delay_response_ms: AtomicUsize::new(0),
            abort_response: AtomicBool::new(false),
            close_after_response: AtomicBool::new(false),
            emit_keep_alive_header: AtomicBool::new(false),
            expected_client_der: Mutex::new(None),
        })
    }
}

struct ConnCtx {
    state: Arc<TestServerState>,
}

impl Drop for ConnCtx {
    fn drop(&mut self) {
        self.state.live_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

struct ReqCtx {
    state: Arc<TestServerState>,
    content_length: usize,
    body: Vec<u8>,
    path: String,
}

impl Drop for ReqCtx {
    fn drop(&mut self) {
        self.state.live_requests.fetch_sub(1, Ordering::SeqCst);
    }
}

extern "C" fn on_bound_cb(ud: *mut c_void, port: u16) {
    let state = unsafe { &*(ud as *const TestServerState) };
    *state.bound_port.lock().unwrap() = Some(port);
}

extern "C" fn create_conn_cb(
    ud: *mut c_void,
    _conn_id: u64,
    _la: *const u8,
    _la_len: usize,
    _lp: u16,
    _ra: *const u8,
    _ra_len: usize,
    _rp: u16,
) -> *mut c_void {
    let state = unsafe { Arc::from_raw(ud as *const TestServerState) };
    let cloned = state.clone();
    std::mem::forget(state);
    cloned.live_connections.fetch_add(1, Ordering::SeqCst);
    Box::into_raw(Box::new(ConnCtx { state: cloned })) as *mut c_void
}

extern "C" fn drop_conn_cb(_ud: *mut c_void, ptr: *mut c_void) {
    unsafe { drop(Box::from_raw(ptr as *mut ConnCtx)) };
}

extern "C" fn verify_client_cb(
    ud: *mut c_void,
    _conn_id: u64,
    der: *const u8,
    der_len: usize,
) -> bool {
    let state = unsafe { &*(ud as *const TestServerState) };
    state.verify_called.fetch_add(1, Ordering::SeqCst);
    let cert = unsafe { std::slice::from_raw_parts(der, der_len) };
    if let Some(expected) = state.expected_client_der.lock().unwrap().as_ref() {
        if cert != expected.as_slice() {
            return false;
        }
    }
    state.allow_client_verify.load(Ordering::SeqCst)
}

extern "C" fn verify_failed_cb(
    ud: *mut c_void,
    _conn: *mut c_void,
    sender: *mut ResponseSenderHandle,
) {
    let state = unsafe { &*(ud as *const TestServerState) };
    state.verify_failed_called.fetch_add(1, Ordering::SeqCst);
    let body = b"unauthorized";
    let resp = format!(
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut wire = resp.into_bytes();
    wire.extend_from_slice(body);
    unsafe { Box::from_raw(sender) }.send(wire, true);
}

extern "C" fn create_req_cb(
    ud: *mut c_void,
    _conn: *mut c_void,
    head: *const ServerRequestHeadFfi,
) -> *mut c_void {
    let state = unsafe { Arc::from_raw(ud as *const TestServerState) };
    let cloned = state.clone();
    std::mem::forget(state);
    cloned.live_requests.fetch_add(1, Ordering::SeqCst);
    let h = unsafe { &*head };
    let path = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(h.path, h.path_len) })
        .into_owned();
    let hdrs = if h.headers.is_null() || h.header_count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(h.headers, h.header_count) }
    };
    let mut cl = 0usize;
    for hdr in hdrs {
        let name = unsafe { std::slice::from_raw_parts(hdr.name, hdr.name_len) };
        if name.eq_ignore_ascii_case(b"content-length") {
            let val = unsafe { std::slice::from_raw_parts(hdr.value, hdr.value_len) };
            cl = std::str::from_utf8(val).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }
    Box::into_raw(Box::new(ReqCtx {
        state: cloned,
        content_length: cl,
        body: Vec::new(),
        path,
    })) as *mut c_void
}

extern "C" fn drop_req_cb(_ud: *mut c_void, ptr: *mut c_void) {
    unsafe { drop(Box::from_raw(ptr as *mut ReqCtx)) };
}

extern "C" fn on_req_header_cb(ud: *mut c_void, req_ptr: *mut c_void) -> bool {
    let state = unsafe { &*(ud as *const TestServerState) };
    let req = unsafe { &*(req_ptr as *const ReqCtx) };
    req.content_length <= state.reject_header_if_body_gt.load(Ordering::SeqCst)
}

extern "C" fn attach_body_cb(_ud: *mut c_void, req_ptr: *mut c_void, body: *const u8, len: usize) {
    let req = unsafe { &mut *(req_ptr as *mut ReqCtx) };
    if !body.is_null() && len > 0 {
        req.body = unsafe { std::slice::from_raw_parts(body, len) }.to_vec();
    }
}

extern "C" fn dispatch_cb(
    ud: *mut c_void,
    req_ptr: *mut c_void,
    sender: *mut ResponseSenderHandle,
) {
    let state = unsafe { Arc::from_raw(ud as *const TestServerState) };
    let cloned = state.clone();
    std::mem::forget(state);
    cloned.dispatched_count.fetch_add(1, Ordering::SeqCst);

    let req = unsafe { &*(req_ptr as *const ReqCtx) };
    let body_out = if req.path == "/echo" {
        req.body.clone()
    } else {
        b"ok".to_vec()
    };

    let delay = cloned.delay_response_ms.load(Ordering::SeqCst);
    let abort = cloned.abort_response.load(Ordering::SeqCst);
    let close = cloned.close_after_response.load(Ordering::SeqCst);
    let emit_ka = cloned.emit_keep_alive_header.load(Ordering::SeqCst);

    let handle = unsafe { Box::from_raw(sender) };
    let build_reply = move || {
        let extra = if emit_ka {
            "Connection: keep-alive\r\n"
        } else {
            ""
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\n{extra}Content-Length: {}\r\n\r\n",
            body_out.len()
        );
        let mut wire = head.into_bytes();
        wire.extend_from_slice(&body_out);
        wire
    };
    if delay > 0 || abort {
        // Send asynchronously from a background thread (matching sds::worker / nvhttp::pin)
        thread::spawn(move || {
            if delay > 0 {
                thread::sleep(Duration::from_millis(delay as u64));
            }
            if abort {
                handle.abort();
                return;
            }
            handle.send(build_reply(), close);
        });
    } else {
        handle.send(build_reply(), close);
    }
}

extern "C" fn on_error_cb(
    ud: *mut c_void,
    _conn: *mut c_void,
    _req: *mut c_void,
    kind: ErrorKind,
    _msg: *const u8,
    _len: usize,
) {
    let state = unsafe { &*(ud as *const TestServerState) };
    state.errors.lock().unwrap().push(kind);
}

struct RunningTestServer {
    state: Arc<TestServerState>,
    port: u16,
    stop_fn: Arc<dyn Fn() + Send + Sync>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl RunningTestServer {
    fn start(mut settings: ServerSettings, with_verify: bool) -> Self {
        let state = TestServerState::new();
        settings.port = 0;
        let ud = Arc::as_ptr(&state) as usize;

        let callbacks = ServerCallbacks {
            user_data: ud,
            on_bound: Some(on_bound_cb),
            create_connection: create_conn_cb,
            drop_connection: drop_conn_cb,
            on_connection_accepted: None,
            on_verify_client: if with_verify {
                Some(verify_client_cb)
            } else {
                None
            },
            on_verify_failed: if with_verify {
                Some(verify_failed_cb)
            } else {
                None
            },
            on_connection_authenticated: None,
            create_request: create_req_cb,
            drop_request: drop_req_cb,
            on_request_header: Some(on_req_header_cb),
            attach_request_body: attach_body_cb,
            dispatch_request: dispatch_cb,
            on_error: Some(on_error_cb),
        };

        let srv = Arc::new(HttpServerInstance::create(settings, callbacks).unwrap());
        let state_bg = state.clone();
        let srv_run = srv.clone();

        let join_handle = thread::spawn(move || {
            srv_run.run().unwrap();
        });

        let port = loop {
            if let Some(p) = *state_bg.bound_port.lock().unwrap() {
                break p;
            }
            thread::sleep(Duration::from_millis(5));
        };

        let srv_stop = srv.clone();
        let stop_fn = Arc::new(move || {
            srv_stop.stop();
        });

        Self {
            state,
            port,
            stop_fn,
            join_handle: Some(join_handle),
        }
    }

    fn stop(&mut self) {
        if let Some(h) = self.join_handle.take() {
            (self.stop_fn)();
            h.join().unwrap();
        }
    }
}

impl Drop for RunningTestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wait_until(pred: impl Fn() -> bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if pred() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    pred()
}

#[test]
fn pq_tls13_only_rejects_tls12_and_classical_kx() {
    let srv_creds = generate_cert("pq_srv", "localhost");
    let srv = RunningTestServer::start(
        ServerSettings {
            port: 0,
            thread_pool_size: 2,
            timeout_request_secs: 5,
            timeout_content_secs: 5,
            max_request_streambuf_size: 64 * 1024,
            max_request_header_size: 64 * 1024,
            address: "127.0.0.1".into(),
            reuse_address: true,
            is_https: true,
            cert_file: Some(srv_creds.cert_path.to_string_lossy().into_owned()),
            key_file: Some(srv_creds.key_path.to_string_lossy().into_owned()),
            verify_file: None,
            require_client_cert: false,
        },
        false,
    );

    // 1. Hardened PQ client succeeds and negotiates X25519MLKEM768 over TLS 1.3.
    let client = HttpClientInstance::create(ClientSettings {
        host: "127.0.0.1".into(),
        port: srv.port,
        default_port: 443,
        is_https: true,
        verify_certificate: false,
        cert_file: None,
        key_file: None,
        verify_file: None,
    })
    .unwrap();
    let resp = client
        .request("GET", "/hello", &[], &[], 5, 5, 1024 * 1024)
        .unwrap();
    assert_eq!(resp.status_code, "200 OK");
    assert_eq!(resp.body, b"ok");

    let rt = tokio::runtime::Runtime::new().unwrap();

    // 2. Raw TLS 1.2-only ClientHello (no supported_versions TLS 1.3 extension) MUST fail handshake.
    let tls12_reply = rt.block_on(async {
        let mut tcp = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
        // Handshake ClientHello body: TLS 1.2 (0x0303), 32-byte zero random,
        // 0-byte session_id, 2 cipher suites (0xc02f, 0xc02b), null compression, no extensions.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x00); // session_id_len = 0
        body.extend_from_slice(&[0x00, 0x04, 0xc0, 0x2f, 0xc0, 0x2b]);
        body.extend_from_slice(&[0x01, 0x00]); // compression methods: [null]
        body.extend_from_slice(&[0x00, 0x00]); // extensions_len = 0

        let hs_len = (body.len() as u32).to_be_bytes();
        let rec_len = ((body.len() + 4) as u16).to_be_bytes();
        let mut record = vec![0x16, 0x03, 0x01, rec_len[0], rec_len[1], 0x01, hs_len[1], hs_len[2], hs_len[3]];
        record.extend_from_slice(&body);

        tcp.write_all(&record).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut out = Vec::new();
            let mut tmp = [0u8; 64];
            while let Ok(k) = tcp.read(&mut tmp).await {
                if k == 0 {
                    break;
                }
                out.extend_from_slice(&tmp[..k]);
            }
            out
        })
        .await
        .expect("server must respond or close promptly on TLS 1.2 ClientHello")
    });
    assert!(
        tls12_reply.is_empty()
            || (tls12_reply.len() >= 7 && tls12_reply[0] == 0x15 && tls12_reply[5] == 0x02),
        "TLS 1.2 ClientHello must fail with fatal TLS alert or immediate close, got: {:02x?}",
        tls12_reply
    );

    // 3. Classical TLS 1.3 client (X25519 + secp256r1 only, NO X25519MLKEM768) MUST fail handshake.
    let mut classical_provider = aws_lc_rs::default_provider();
    classical_provider.kx_groups = vec![
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::SECP256R1,
    ];
    let classical_cfg = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(classical_provider.clone()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllServerCerts {
                algs: classical_provider.signature_verification_algorithms,
            }))
            .with_no_client_auth(),
    );
    let classical_res = rt.block_on(async {
        let tcp = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
        TlsConnector::from(classical_cfg)
            .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
            .await
    });
    assert!(
        classical_res.is_err(),
        "Classical-only TLS 1.3 client must be rejected"
    );

    // 4. Verify PQ client explicitly confirms negotiated KX group is X25519MLKEM768.
    let mut pq_provider = aws_lc_rs::default_provider();
    pq_provider.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    let pq_cfg = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(pq_provider.clone()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllServerCerts {
                algs: pq_provider.signature_verification_algorithms,
            }))
            .with_no_client_auth(),
    );
    let pq_stream = rt
        .block_on(async {
            let tcp = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
            TlsConnector::from(pq_cfg)
                .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
                .await
        })
        .unwrap();
    assert_eq!(
        pq_stream
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
        rustls::NamedGroup::X25519MLKEM768
    );
}

#[derive(Debug)]
struct MismatchedKeyClientResolver {
    cert: CertificateDer<'static>,
    wrong_key: Arc<dyn SigningKey>,
}

impl ResolvesClientCert for MismatchedKeyClientResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::new(CertifiedKey::new(
            vec![self.cert.clone()],
            self.wrong_key.clone(),
        )))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[test]
fn mtls_rejects_missing_cert_mismatched_signature_and_calls_verify_failed() {
    let srv_creds = generate_cert("mtls_srv", "localhost");
    let client_ok = generate_cert("mtls_cli_ok", "client-ok");
    let client_bad = generate_cert("mtls_cli_bad", "client-bad");

    let srv = RunningTestServer::start(
        ServerSettings {
            port: 0,
            thread_pool_size: 2,
            timeout_request_secs: 5,
            timeout_content_secs: 5,
            max_request_streambuf_size: 64 * 1024,
            max_request_header_size: 64 * 1024,
            address: "127.0.0.1".into(),
            reuse_address: true,
            is_https: true,
            cert_file: Some(srv_creds.cert_path.to_string_lossy().into_owned()),
            key_file: Some(srv_creds.key_path.to_string_lossy().into_owned()),
            verify_file: None,
            require_client_cert: true,
        },
        true,
    );
    *srv.state.expected_client_der.lock().unwrap() = Some(client_ok.cert_der.clone());

    // 1. Missing client certificate is rejected at TLS handshake (verify callback never reached).
    let anon = HttpClientInstance::create(ClientSettings {
        host: "127.0.0.1".into(),
        port: srv.port,
        default_port: 443,
        is_https: true,
        verify_certificate: false,
        cert_file: None,
        key_file: None,
        verify_file: None,
    })
    .unwrap();
    let anon_res = anon.request("GET", "/test", &[], &[], 5, 5, 1024 * 1024);
    assert!(anon_res.is_err());
    assert_eq!(srv.state.verify_called.load(Ordering::SeqCst), 0);

    // 2. Forged client presenting client_ok's cert but signing CertificateVerify with client_bad's key!
    let mut pq_provider = aws_lc_rs::default_provider();
    pq_provider.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    let wrong_key = pq_provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(client_bad.key_der.clone().into()))
        .unwrap();
    let resolver = Arc::new(MismatchedKeyClientResolver {
        cert: CertificateDer::from(client_ok.cert_der.clone()),
        wrong_key,
    });
    let forged_cfg = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(pq_provider.clone()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllServerCerts {
                algs: pq_provider.signature_verification_algorithms,
            }))
            .with_client_cert_resolver(resolver),
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    let forged_res = rt.block_on(async {
        let tcp = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
        let mut tls = TlsConnector::from(forged_cfg)
            .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
            .await?;
        tls.write_all(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        tls.flush().await?;
        let mut buf = [0u8; 64];
        tls.read(&mut buf).await
    });
    assert!(
        forged_res.is_err(),
        "Mismatched CertificateVerify signature MUST fail TLS handshake"
    );
    assert_eq!(srv.state.verify_called.load(Ordering::SeqCst), 0);

    // 3. Unpaired valid client cert completes TLS handshake, hits verify callback, triggers on_verify_failed 401 and closes.
    let bad_cli = HttpClientInstance::create(ClientSettings {
        host: "127.0.0.1".into(),
        port: srv.port,
        default_port: 443,
        is_https: true,
        verify_certificate: false,
        cert_file: Some(client_bad.cert_path.to_string_lossy().into_owned()),
        key_file: Some(client_bad.key_path.to_string_lossy().into_owned()),
        verify_file: None,
    })
    .unwrap();
    let bad_resp = bad_cli
        .request("GET", "/test", &[], &[], 5, 5, 1024 * 1024)
        .unwrap();
    assert_eq!(bad_resp.status_code, "401 Unauthorized");
    assert_eq!(bad_resp.body, b"unauthorized");
    assert_eq!(srv.state.verify_failed_called.load(Ordering::SeqCst), 1);
    assert_eq!(srv.state.dispatched_count.load(Ordering::SeqCst), 0);

    // 4. Paired client cert succeeds end-to-end.
    let ok_cli = HttpClientInstance::create(ClientSettings {
        host: "127.0.0.1".into(),
        port: srv.port,
        default_port: 443,
        is_https: true,
        verify_certificate: false,
        cert_file: Some(client_ok.cert_path.to_string_lossy().into_owned()),
        key_file: Some(client_ok.key_path.to_string_lossy().into_owned()),
        verify_file: None,
    })
    .unwrap();
    let ok_resp = ok_cli
        .request("GET", "/test", &[], &[], 5, 5, 1024 * 1024)
        .unwrap();
    assert_eq!(ok_resp.status_code, "200 OK");
    assert_eq!(srv.state.dispatched_count.load(Ordering::SeqCst), 1);
    drop(ok_cli);
    assert!(wait_until(|| srv.state.live_connections.load(Ordering::SeqCst) == 0));
}

#[test]
fn http_framing_smuggling_timeout_and_lifecycle() {
    let mut srv = RunningTestServer::start(
        ServerSettings {
            port: 0,
            thread_pool_size: 2,
            timeout_request_secs: 2,
            timeout_content_secs: 1,
            max_request_streambuf_size: 4096,
            max_request_header_size: 1024,
            address: "127.0.0.1".into(),
            reuse_address: true,
            is_https: false,
            cert_file: None,
            key_file: None,
            verify_file: None,
            require_client_cert: false,
        },
        false,
    );

    // Reject malformed heads / Transfer-Encoding / duplicate CL / oversized header without dispatch
    let bad_payloads: &[&[u8]] = &[
        b"GET /x HTTP/1.1\nHost: a\r\n\r\n",
        b"GET /\0 HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET /x HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
        b"GET /x HTTP/1.1\r\nBad Name: 1\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
        b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: +1\r\n\r\na",
        b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5000\r\n\r\n",
    ];
    for payload in bad_payloads {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        let _ = s.write_all(payload);
        let mut buf = [0u8; 64];
        let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
        assert_eq!(n, 0, "expected immediate close without body for {:?}", String::from_utf8_lossy(payload));
    }
    assert_eq!(srv.state.dispatched_count.load(Ordering::SeqCst), 0);

    // Oversized header (> 1024 bytes) closes immediately
    {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        let big = format!("GET /x HTTP/1.1\r\nX-Pad: {}\r\n\r\n", "a".repeat(2048));
        let _ = s.write_all(big.as_bytes());
        let mut buf = [0u8; 64];
        let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
        assert_eq!(n, 0);
    }

    // on_request_header rejects before body is read
    srv.state.reject_header_if_body_gt.store(100, Ordering::SeqCst);
    {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        s.write_all(b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 200\r\n\r\n")
            .unwrap();
        let mut buf = [0u8; 64];
        let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
        assert_eq!(n, 0);
    }
    srv.state
        .reject_header_if_body_gt
        .store(usize::MAX, Ordering::SeqCst);
    assert_eq!(srv.state.dispatched_count.load(Ordering::SeqCst), 0);

    // timeout_content fires on stalled partial body and drops request lease
    {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        s.write_all(b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 500\r\n\r\nhi")
            .unwrap();
        let mut buf = [0u8; 64];
        let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
        assert_eq!(n, 0);
    }
    assert!(wait_until(|| srv.state.live_requests.load(Ordering::SeqCst) == 0));

    // Keep-alive multiple requests + async background reply releases per-request lease every cycle
    srv.state.delay_response_ms.store(30, Ordering::SeqCst);
    let client = HttpClientInstance::create(ClientSettings {
        host: "127.0.0.1".into(),
        port: srv.port,
        default_port: 80,
        is_https: false,
        verify_certificate: false,
        cert_file: None,
        key_file: None,
        verify_file: None,
    })
    .unwrap();
    for i in 0..3 {
        let payload = format!("msg-{i}");
        let r = client
            .request("POST", "/echo", &[], payload.as_bytes(), 5, 5, 1024 * 1024)
            .unwrap();
        assert_eq!(r.status_code, "200 OK");
        assert_eq!(r.body, payload.as_bytes());
        assert!(wait_until(|| srv.state.live_requests.load(Ordering::SeqCst) == 0));
        assert_eq!(srv.state.live_connections.load(Ordering::SeqCst), 1);
    }

    // Response::abort() closes cleanly without hanging
    srv.state.delay_response_ms.store(0, Ordering::SeqCst);
    srv.state.abort_response.store(true, Ordering::SeqCst);
    assert!(client
        .request("GET", "/abort", &[], &[], 5, 5, 1024 * 1024)
        .is_err());
    assert!(wait_until(|| srv.state.live_requests.load(Ordering::SeqCst) == 0));
    assert!(wait_until(|| srv.state.live_connections.load(Ordering::SeqCst) == 0));

    // close_connection_after_response injects Connection: close and drops socket
    srv.state.abort_response.store(false, Ordering::SeqCst);
    srv.state.close_after_response.store(true, Ordering::SeqCst);
    let r_close = client
        .request("GET", "/close", &[], &[], 5, 5, 1024 * 1024)
        .unwrap();
    assert_eq!(r_close.status_code, "200 OK");
    assert!(r_close
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close")));
    assert!(wait_until(|| srv.state.live_connections.load(Ordering::SeqCst) == 0));

    drop(client);
    srv.stop();
    assert_eq!(srv.state.live_connections.load(Ordering::SeqCst), 0);
    assert_eq!(srv.state.live_requests.load(Ordering::SeqCst), 0);
}

#[test]
fn slowloris_header_drip_times_out_within_single_deadline() {
    let mut srv = RunningTestServer::start(
        ServerSettings {
            port: 0,
            thread_pool_size: 2,
            timeout_request_secs: 1,
            timeout_content_secs: 1,
            max_request_streambuf_size: 4096,
            max_request_header_size: 1024,
            address: "127.0.0.1".into(),
            reuse_address: true,
            is_https: false,
            cert_file: None,
            key_file: None,
            verify_file: None,
            require_client_cert: false,
        },
        false,
    );

    let start = std::time::Instant::now();
    let mut sock = std::net::TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    // Drip bytes slower than total completion within 1s, faster than 1s per-read
    let msg = b"GET /slow HTTP/1.1\r\nHost: localhost\r\n";
    let mut i = 0;
    while start.elapsed() < Duration::from_secs(3) {
        let byte = if i < msg.len() { msg[i] } else { b'X' };
        i += 1;
        if sock.write_all(&[byte]).is_err() {
            break;
        }
        let mut buf = [0u8; 8];
        sock.set_nonblocking(true).unwrap();
        match std::io::Read::read(&mut sock, &mut buf) {
            Ok(0) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
            Ok(_) => {}
        }
        sock.set_nonblocking(false).unwrap();
        thread::sleep(Duration::from_millis(250));
    }
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "slowloris drip must time out promptly"
    );
    assert!(wait_until(|| srv
        .state
        .errors
        .lock()
        .unwrap()
        .contains(&ErrorKind::TimedOut)));
    assert_eq!(srv.state.dispatched_count.load(Ordering::SeqCst), 0);
    srv.stop();
}

#[test]
fn rfc9112_host_header_enforcement_and_connection_close_rewrite() {
    let mut srv = RunningTestServer::start(
        ServerSettings {
            port: 0,
            thread_pool_size: 2,
            timeout_request_secs: 2,
            timeout_content_secs: 2,
            max_request_streambuf_size: 4096,
            max_request_header_size: 1024,
            address: "127.0.0.1".into(),
            reuse_address: true,
            is_https: false,
            cert_file: None,
            key_file: None,
            verify_file: None,
            require_client_cert: false,
        },
        false,
    );

    for bad in [
        &b"GET /x HTTP/1.1\r\n\r\n"[..],
        &b"GET /x HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"[..],
        &b"GET /x HTTP/1.1\r\nHost: bad host\r\n\r\n"[..],
    ] {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        s.write_all(bad).unwrap();
        let mut buf = [0u8; 64];
        let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
        assert_eq!(n, 0);
    }
    assert_eq!(srv.state.dispatched_count.load(Ordering::SeqCst), 0);

    // HTTP/1.0 without Host succeeds
    {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        s.write_all(b"GET /ok HTTP/1.0\r\n\r\n").unwrap();
        let mut raw = String::new();
        std::io::Read::read_to_string(&mut s, &mut raw).unwrap();
        assert!(raw.starts_with("HTTP/1.1 200 OK"));
        assert!(raw.ends_with("ok"));
    }

    // Handler emitting Connection: keep-alive with close_connection=true must rewrite to Connection: close
    srv.state
        .emit_keep_alive_header
        .store(true, Ordering::SeqCst);
    srv.state.close_after_response.store(true, Ordering::SeqCst);
    let client = HttpClientInstance::create(ClientSettings {
        host: "127.0.0.1".into(),
        port: srv.port,
        default_port: 80,
        is_https: false,
        verify_certificate: false,
        cert_file: None,
        key_file: None,
        verify_file: None,
    })
    .unwrap();
    let resp = client
        .request("GET", "/rewrite", &[], &[], 5, 5, 1024 * 1024)
        .unwrap();
    assert_eq!(resp.status_code, "200 OK");
    assert!(resp
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close")));
    assert!(!resp.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("connection") && v.to_ascii_lowercase().contains("keep-alive")
    }));
    assert!(wait_until(|| srv.state.live_connections.load(Ordering::SeqCst) == 0));
    srv.stop();
}

#[test]
fn client_default_port_crlf_rejection_and_response_smuggling_rejection() {
    let mut srv = RunningTestServer::start(
        ServerSettings {
            port: 0,
            thread_pool_size: 2,
            timeout_request_secs: 2,
            timeout_content_secs: 2,
            max_request_streambuf_size: 4096,
            max_request_header_size: 1024,
            address: "127.0.0.1".into(),
            reuse_address: true,
            is_https: false,
            cert_file: None,
            key_file: None,
            verify_file: None,
            require_client_cert: false,
        },
        false,
    );

    // 1. port == 0 falls back to default_port
    let cli = HttpClientInstance::create(ClientSettings {
        host: "127.0.0.1".into(),
        port: 0,
        default_port: srv.port,
        is_https: false,
        verify_certificate: false,
        cert_file: None,
        key_file: None,
        verify_file: None,
    })
    .unwrap();
    let r = cli
        .request("GET", "/ok", &[], &[], 5, 5, 1024 * 1024)
        .unwrap();
    assert_eq!(r.status_code, "200 OK");
    assert_eq!(r.body, b"ok");

    // 2. Reject CRLF/CTL injection in method, path, header name, and header value
    assert_eq!(
        cli.request("GET\r\n", "/", &[], &[], 5, 5, 1024)
            .err()
            .map(|e| e.0),
        Some(ErrorKind::Protocol)
    );
    assert_eq!(
        cli.request("GET", "/bad\r\npath", &[], &[], 5, 5, 1024)
            .err()
            .map(|e| e.0),
        Some(ErrorKind::Protocol)
    );
    assert_eq!(
        cli.request(
            "GET",
            "/",
            &[("Bad Name".into(), "ok".into())],
            &[],
            5,
            5,
            1024
        )
        .err()
        .map(|e| e.0),
        Some(ErrorKind::Protocol)
    );
    assert_eq!(
        cli.request(
            "GET",
            "/",
            &[("X-Test".into(), "ok\r\nInjected: 1".into())],
            &[],
            5,
            5,
            1024
        )
        .err()
        .map(|e| e.0),
        Some(ErrorKind::Protocol)
    );
    srv.stop();

    // 3. Mock server responses testing duplicate CL, TE+CL, and HTTP/1.1 close-delimited body
    let run_mock = |raw_resp: &'static [u8]| -> Result<sds_http_rs::client::ClientResponseData, (ErrorKind, String)> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut req_buf = [0u8; 512];
            let _ = std::io::Read::read(&mut conn, &mut req_buf);
            let _ = conn.write_all(raw_resp);
            let _ = conn.shutdown(std::net::Shutdown::Both);
        });
        let mock_cli = HttpClientInstance::create(ClientSettings {
            host: "127.0.0.1".into(),
            port,
            default_port: 80,
            is_https: false,
            verify_certificate: false,
            cert_file: None,
            key_file: None,
            verify_file: None,
        })
        .unwrap();
        let res = mock_cli.request("GET", "/", &[], &[], 5, 5, 1024 * 1024);
        handle.join().unwrap();
        res
    };

    assert_eq!(
        run_mock(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nab")
            .err()
            .map(|e| e.0),
        Some(ErrorKind::Protocol)
    );
    assert_eq!(
        run_mock(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\nab\r\n0\r\n\r\n")
            .err()
            .map(|e| e.0),
        Some(ErrorKind::Protocol)
    );
    let eof_ok = run_mock(b"HTTP/1.1 200 OK\r\n\r\nhello-eof").unwrap();
    assert_eq!(eof_ok.body, b"hello-eof");
}

#[test]
fn pq_tls13_http_upgrade_raw_binary_stream_and_backpressure() {
    let srv_cert = generate_cert("upg_srv", "127.0.0.1");
    let cli_cert = generate_cert("upg_cli", "moonlight-client");

    #[derive(Default)]
    struct UpgradeState {
        stream: Mutex<Option<Arc<sds_http_rs::server::RawStreamHandle>>>,
        client_rx: Mutex<Vec<u8>>,
        closed: AtomicBool,
    }

    extern "C" fn on_client_data(ud: *mut c_void, data: *const u8, len: usize) {
        let st = unsafe { &*(ud as *const UpgradeState) };
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        st.client_rx.lock().unwrap().extend_from_slice(slice);
    }

    extern "C" fn on_closed(ud: *mut c_void) {
        let st = unsafe { &*(ud as *const UpgradeState) };
        st.closed.store(true, Ordering::Release);
    }

    struct Ctx {
        bound_port: Mutex<Option<u16>>,
        state: Arc<UpgradeState>,
    }

    extern "C" fn on_bound(ud: *mut c_void, port: u16) {
        let ctx = unsafe { &*(ud as *const Ctx) };
        *ctx.bound_port.lock().unwrap() = Some(port);
    }
    extern "C" fn create_conn(
        _: *mut c_void,
        _: u64,
        _: *const u8,
        _: usize,
        _: u16,
        _: *const u8,
        _: usize,
        _: u16,
    ) -> *mut c_void {
        Box::into_raw(Box::new(1u8)) as *mut c_void
    }
    extern "C" fn drop_conn(_: *mut c_void, p: *mut c_void) {
        if !p.is_null() {
            unsafe { drop(Box::from_raw(p as *mut u8)) };
        }
    }
    extern "C" fn create_req(
        _: *mut c_void,
        _: *mut c_void,
        _: *const ServerRequestHeadFfi,
    ) -> *mut c_void {
        Box::into_raw(Box::new(2u8)) as *mut c_void
    }
    extern "C" fn drop_req(_: *mut c_void, p: *mut c_void) {
        if !p.is_null() {
            unsafe { drop(Box::from_raw(p as *mut u8)) };
        }
    }
    extern "C" fn attach_body(_: *mut c_void, _: *mut c_void, _: *const u8, _: usize) {}
    extern "C" fn dispatch_req(
        ud: *mut c_void,
        _: *mut c_void,
        sender: *mut ResponseSenderHandle,
    ) {
        let ctx = unsafe { &*(ud as *const Ctx) };
        let sender = unsafe { Box::from_raw(sender) };
        let head = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: sds-lossless-v1\r\n\r\n".to_vec();
        let st_ptr = Arc::as_ptr(&ctx.state) as usize;
        let raw = sender
            .upgrade(head, 2, Some(on_client_data), Some(on_closed), st_ptr)
            .expect("upgrade should succeed");
        *ctx.state.stream.lock().unwrap() = Some(raw);
    }

    let state = Arc::new(UpgradeState::default());
    let ctx = Box::new(Ctx {
        bound_port: Mutex::new(None),
        state: state.clone(),
    });
    let ctx_ptr = Box::into_raw(ctx);

    let cbs = ServerCallbacks {
        user_data: ctx_ptr as usize,
        on_bound: Some(on_bound),
        create_connection: create_conn,
        drop_connection: drop_conn,
        on_connection_accepted: None,
        on_verify_client: None,
        on_verify_failed: None,
        on_connection_authenticated: None,
        create_request: create_req,
        drop_request: drop_req,
        on_request_header: None,
        attach_request_body: attach_body,
        dispatch_request: dispatch_req,
        on_error: None,
    };

    let srv = Arc::new(
        HttpServerInstance::create(
            ServerSettings {
                port: 0,
                thread_pool_size: 2,
                timeout_request_secs: 5,
                timeout_content_secs: 5,
                max_request_streambuf_size: 64 * 1024,
                max_request_header_size: 16 * 1024,
                address: "127.0.0.1".into(),
                reuse_address: true,
                is_https: true,
                cert_file: Some(srv_cert.cert_path.to_string_lossy().into_owned()),
                key_file: Some(srv_cert.key_path.to_string_lossy().into_owned()),
                verify_file: None,
                require_client_cert: true,
            },
            cbs,
        )
        .unwrap(),
    );

    let srv_run = srv.clone();
    let srv_thread = thread::spawn(move || {
        srv_run.run().unwrap();
    });

    let port = loop {
        let p = unsafe { (*ctx_ptr).bound_port.lock().unwrap() };
        if let Some(port) = *p {
            break port;
        }
        drop(p);
        thread::sleep(Duration::from_millis(5));
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
        let verifier = Arc::new(AcceptAllServerCerts {
            algs: provider.signature_verification_algorithms,
        });
        let cert_der = CertificateDer::from(cli_cert.cert_der.clone());
        let key_der = PrivateKeyDer::try_from(cli_cert.key_der.clone()).unwrap();
        let client_cfg = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![cert_der], key_der)
            .unwrap();

        let connector = TlsConnector::from(Arc::new(client_cfg));
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let sni = ServerName::try_from("127.0.0.1").unwrap();
        let mut tls = connector.connect(sni, tcp).await.unwrap();

        tls.write_all(
            b"GET /sds/v1/lossless-stream HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: sds-lossless-v1\r\n\r\n",
        )
        .await
        .unwrap();
        tls.flush().await.unwrap();

        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = tls.read(&mut b).await.unwrap();
            assert!(n > 0);
            head.push(b[0]);
        }
        assert!(std::str::from_utf8(&head).unwrap().starts_with("HTTP/1.1 101 "));

        let raw = loop {
            if let Some(r) = state.stream.lock().unwrap().clone() {
                break r;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };

        // Send 2 binary frames (bounded channel) and confirm client receives them intact
        let p1 = vec![0x53u8, 0x44, 0x4C, 0x4C, 1, 2, 3, 4];
        let p2 = vec![0xAAu8; 65536];
        assert!(raw.try_send(p1.clone()).is_ok());
        assert!(raw.try_send(p2.clone()).is_ok());

        let mut got = vec![0u8; p1.len() + p2.len()];
        tls.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..p1.len()], p1.as_slice());
        assert_eq!(&got[p1.len()..], p2.as_slice());

        // Send 12-byte SDLC control msg client -> server
        let ctrl = [b'S', b'D', b'L', b'C', 1, 0, 1, 0, 42, 0, 0, 0];
        tls.write_all(&ctrl).await.unwrap();
        tls.flush().await.unwrap();

        for _ in 0..100 {
            if state.client_rx.lock().unwrap().len() >= ctrl.len() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(state.client_rx.lock().unwrap().as_slice(), &ctrl);

        raw.close();
        drop(tls);
    });

    for _ in 0..100 {
        if state.closed.load(Ordering::Acquire) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(state.closed.load(Ordering::Acquire));

    srv.stop();
    srv_thread.join().unwrap();
    unsafe { drop(Box::from_raw(ctx_ptr)) };
}

#[test]
fn upgrade_stream_closes_cleanly_on_server_shutdown_and_fires_on_closed_once() {
    let srv_cert = generate_cert("srv_up_shut", "127.0.0.1");
    let cli_cert = generate_cert("cli_up_shut", "client");

    #[derive(Default)]
    struct State {
        stream: Mutex<Option<Arc<sds_http_rs::server::RawStreamHandle>>>,
        closed_count: AtomicUsize,
    }
    struct Ctx {
        bound_port: Mutex<Option<u16>>,
        state: Arc<State>,
    }

    extern "C" fn on_bound(ud: *mut c_void, port: u16) {
        let ctx = unsafe { &*(ud as *const Ctx) };
        *ctx.bound_port.lock().unwrap() = Some(port);
    }
    extern "C" fn create_conn(
        _: *mut c_void,
        _: u64,
        _: *const u8,
        _: usize,
        _: u16,
        _: *const u8,
        _: usize,
        _: u16,
    ) -> *mut c_void {
        Box::into_raw(Box::new(1u8)) as *mut c_void
    }
    extern "C" fn drop_conn(_: *mut c_void, p: *mut c_void) {
        if !p.is_null() {
            unsafe { drop(Box::from_raw(p as *mut u8)) };
        }
    }
    extern "C" fn create_req(
        _: *mut c_void,
        _: *mut c_void,
        _: *const ServerRequestHeadFfi,
    ) -> *mut c_void {
        Box::into_raw(Box::new(2u8)) as *mut c_void
    }
    extern "C" fn drop_req(_: *mut c_void, p: *mut c_void) {
        if !p.is_null() {
            unsafe { drop(Box::from_raw(p as *mut u8)) };
        }
    }
    extern "C" fn attach_body(_: *mut c_void, _: *mut c_void, _: *const u8, _: usize) {}
    extern "C" fn on_closed_cb(ud: *mut c_void) {
        let st = unsafe { &*(ud as *const State) };
        st.closed_count.fetch_add(1, Ordering::AcqRel);
    }
    extern "C" fn dispatch_req(
        ud: *mut c_void,
        _: *mut c_void,
        sender: *mut ResponseSenderHandle,
    ) {
        let ctx = unsafe { &*(ud as *const Ctx) };
        let sender = unsafe { Box::from_raw(sender) };
        let head = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: sds-lossless-v1\r\n\r\n".to_vec();
        let st_ptr = Arc::as_ptr(&ctx.state) as usize;
        let raw = sender
            .upgrade(head, 2, None, Some(on_closed_cb), st_ptr)
            .expect("upgrade should succeed");
        *ctx.state.stream.lock().unwrap() = Some(raw);
    }

    let state = Arc::new(State::default());
    let ctx = Box::new(Ctx {
        bound_port: Mutex::new(None),
        state: state.clone(),
    });
    let ctx_ptr = Box::into_raw(ctx);

    let cbs = ServerCallbacks {
        user_data: ctx_ptr as usize,
        on_bound: Some(on_bound),
        create_connection: create_conn,
        drop_connection: drop_conn,
        on_connection_accepted: None,
        on_verify_client: None,
        on_verify_failed: None,
        on_connection_authenticated: None,
        create_request: create_req,
        drop_request: drop_req,
        on_request_header: None,
        attach_request_body: attach_body,
        dispatch_request: dispatch_req,
        on_error: None,
    };

    let srv = Arc::new(
        HttpServerInstance::create(
            ServerSettings {
                port: 0,
                thread_pool_size: 2,
                timeout_request_secs: 5,
                timeout_content_secs: 5,
                max_request_streambuf_size: 64 * 1024,
                max_request_header_size: 16 * 1024,
                address: "127.0.0.1".into(),
                reuse_address: true,
                is_https: true,
                cert_file: Some(srv_cert.cert_path.to_string_lossy().into_owned()),
                key_file: Some(srv_cert.key_path.to_string_lossy().into_owned()),
                verify_file: None,
                require_client_cert: true,
            },
            cbs,
        )
        .unwrap(),
    );

    let srv_run = srv.clone();
    let srv_thread = thread::spawn(move || {
        srv_run.run().unwrap();
    });

    let port = loop {
        let p = unsafe { (*ctx_ptr).bound_port.lock().unwrap() };
        if let Some(port) = *p {
            break port;
        }
        drop(p);
        thread::sleep(Duration::from_millis(5));
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _kept_tls = rt.block_on(async {
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
        let verifier = Arc::new(AcceptAllServerCerts {
            algs: provider.signature_verification_algorithms,
        });
        let cert_der = CertificateDer::from(cli_cert.cert_der.clone());
        let key_der = PrivateKeyDer::try_from(cli_cert.key_der.clone()).unwrap();
        let client_cfg = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![cert_der], key_der)
            .unwrap();
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let sni = ServerName::try_from("127.0.0.1").unwrap();
        let mut tls = connector.connect(sni, tcp).await.unwrap();
        tls.write_all(
            b"GET /sds/v1/lossless-stream HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: sds-lossless-v1\r\n\r\n",
        )
        .await
        .unwrap();
        tls.flush().await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = tls.read(&mut b).await.unwrap();
            assert!(n > 0);
            head.push(b[0]);
        }
        tls
    });

    // Server stop while client TLS socket is still open must NOT hang and must fire on_closed once
    srv.stop();
    srv_thread.join().unwrap();
    assert_eq!(state.closed_count.load(Ordering::Acquire), 1);
    if let Some(h) = state.stream.lock().unwrap().take() {
        assert!(h.is_closed());
    }
    unsafe { drop(Box::from_raw(ctx_ptr)) };
}
