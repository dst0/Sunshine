use crate::client::{ClientSettings, HttpClientInstance};
use crate::http::{
    base64_decode, base64_encode, has_canonical_header_lines, parse_query_string,
    percent_decode_bytes, percent_encode_bytes, validate_request_framing,
};
use crate::server::{
    ErrorKind, HeaderSliceFfi, HttpServerInstance, ResponseSenderHandle, ServerCallbacks,
    ServerRequestHeadFfi, ServerSettings,
};
use std::ffi::{c_char, c_void, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[repr(C)]
pub struct SdsHttpBytes {
    pub data: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl SdsHttpBytes {
    pub fn empty() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    pub fn from_vec(mut v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self::empty();
        }
        let data = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        std::mem::forget(v);
        Self { data, len, cap }
    }

    pub fn from_string(s: String) -> Self {
        Self::from_vec(s.into_bytes())
    }
}

#[repr(C)]
pub struct SdsHttpHeaderOwned {
    pub name: SdsHttpBytes,
    pub value: SdsHttpBytes,
}

#[repr(C)]
pub struct SdsHttpHeaderVec {
    pub items: *mut SdsHttpHeaderOwned,
    pub len: usize,
    pub cap: usize,
}

impl SdsHttpHeaderVec {
    pub fn empty() -> Self {
        Self {
            items: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    pub fn from_vec(mut v: Vec<SdsHttpHeaderOwned>) -> Self {
        if v.is_empty() {
            return Self::empty();
        }
        let items = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        std::mem::forget(v);
        Self { items, len, cap }
    }
}

#[repr(C)]
pub struct SdsHttpServerConfig {
    pub port: u16,
    pub thread_pool_size: usize,
    pub timeout_request_secs: i64,
    pub timeout_content_secs: i64,
    pub max_request_streambuf_size: usize,
    pub max_request_header_size: usize,
    pub address: *const c_char,
    pub reuse_address: bool,
    pub fast_open: bool,
    pub is_https: bool,
    pub cert_file: *const c_char,
    pub key_file: *const c_char,
    pub verify_file: *const c_char,
    pub require_client_cert: bool,
}

#[repr(C)]
pub struct SdsHttpServerCallbacks {
    pub user_data: *mut c_void,
    pub on_bound: Option<extern "C" fn(*mut c_void, u16)>,
    pub create_connection: Option<
        extern "C" fn(
            *mut c_void,
            u64,
            *const u8,
            usize,
            u16,
            *const u8,
            usize,
            u16,
        ) -> *mut c_void,
    >,
    pub drop_connection: Option<extern "C" fn(*mut c_void, *mut c_void)>,
    pub on_connection_accepted: Option<extern "C" fn(*mut c_void, *mut c_void) -> bool>,
    pub on_verify_client: Option<extern "C" fn(*mut c_void, u64, *const u8, usize) -> bool>,
    pub on_verify_failed: Option<extern "C" fn(*mut c_void, *mut c_void, *mut ResponseSenderHandle)>,
    pub on_connection_authenticated: Option<extern "C" fn(*mut c_void, *mut c_void) -> bool>,
    pub create_request:
        Option<extern "C" fn(*mut c_void, *mut c_void, *const ServerRequestHeadFfi) -> *mut c_void>,
    pub drop_request: Option<extern "C" fn(*mut c_void, *mut c_void)>,
    pub on_request_header: Option<extern "C" fn(*mut c_void, *mut c_void) -> bool>,
    pub attach_request_body: Option<extern "C" fn(*mut c_void, *mut c_void, *const u8, usize)>,
    pub dispatch_request: Option<extern "C" fn(*mut c_void, *mut c_void, *mut ResponseSenderHandle)>,
    pub on_error: Option<
        extern "C" fn(*mut c_void, *mut c_void, *mut c_void, ErrorKind, *const u8, usize),
    >,
}

#[repr(C)]
pub struct SdsHttpClientConfig {
    pub host: *const c_char,
    pub port: u16,
    pub default_port: u16,
    pub is_https: bool,
    pub verify_certificate: bool,
    pub cert_file: *const c_char,
    pub key_file: *const c_char,
    pub verify_file: *const c_char,
}

#[repr(C)]
pub struct SdsHttpClientResponse {
    pub ok: bool,
    pub error_kind: ErrorKind,
    pub error_message: SdsHttpBytes,
    pub http_version: SdsHttpBytes,
    pub status_code: SdsHttpBytes,
    pub headers: SdsHttpHeaderVec,
    pub body: SdsHttpBytes,
}

impl SdsHttpClientResponse {
    fn error(kind: ErrorKind, msg: String) -> Self {
        Self {
            ok: false,
            error_kind: kind,
            error_message: SdsHttpBytes::from_string(msg),
            http_version: SdsHttpBytes::empty(),
            status_code: SdsHttpBytes::empty(),
            headers: SdsHttpHeaderVec::empty(),
            body: SdsHttpBytes::empty(),
        }
    }
}

#[inline]
unsafe fn bytes_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

#[inline]
unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

#[inline]
unsafe fn cstr_to_opt_nonempty(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

#[inline]
unsafe fn write_out_error(out_error: *mut SdsHttpBytes, msg: String) {
    if !out_error.is_null() {
        *out_error = SdsHttpBytes::from_string(msg);
    }
}

/// # Safety
/// `buf` must have been returned by an `sds_http_*` FFI call and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn sds_http_bytes_free(buf: SdsHttpBytes) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !buf.data.is_null() && buf.cap > 0 {
            unsafe {
                drop(Vec::from_raw_parts(buf.data, buf.len, buf.cap));
            }
        }
    }));
}

/// # Safety
/// `vec` must have been returned by an `sds_http_*` FFI call and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn sds_http_header_vec_free(vec: SdsHttpHeaderVec) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !vec.items.is_null() && vec.cap > 0 {
            unsafe {
                let items = Vec::from_raw_parts(vec.items, vec.len, vec.cap);
                for item in items {
                    sds_http_bytes_free(item.name);
                    sds_http_bytes_free(item.value);
                }
            }
        }
    }));
}

/// # Safety
/// If `raw_len > 0`, `raw` must point to `raw_len` valid bytes for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn sds_http_has_canonical_header_lines(raw: *const u8, raw_len: usize) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { bytes_slice(raw, raw_len) };
        has_canonical_header_lines(slice)
    }))
    .unwrap_or(false)
}

/// # Safety
/// All non-null slices (`raw`/`raw_len`, `headers`/`header_count`) and optional `out_content_length`
/// must point to valid memory for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn sds_http_validate_request_framing(
    raw: *const u8,
    raw_len: usize,
    headers: *const HeaderSliceFfi,
    header_count: usize,
    max_body_size: usize,
    out_content_length: *mut usize,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let raw_slice = unsafe { bytes_slice(raw, raw_len) };
        let hdr_slices = if headers.is_null() || header_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(headers, header_count) }
        };
        let mut pairs = Vec::with_capacity(hdr_slices.len());
        for h in hdr_slices {
            let name = match std::str::from_utf8(unsafe { bytes_slice(h.name, h.name_len) }) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let val = match std::str::from_utf8(unsafe { bytes_slice(h.value, h.value_len) }) {
                Ok(s) => s,
                Err(_) => return false,
            };
            pairs.push((name, val));
        }
        match validate_request_framing(raw_slice, pairs, max_body_size) {
            Ok(len) => {
                if !out_content_length.is_null() {
                    unsafe { *out_content_length = len };
                }
                true
            }
            Err(_) => false,
        }
    }))
    .unwrap_or(false)
}

/// # Safety
/// If `len > 0`, `data` must point to `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn sds_http_base64_encode(data: *const u8, len: usize) -> SdsHttpBytes {
    catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { bytes_slice(data, len) };
        SdsHttpBytes::from_vec(base64_encode(slice))
    }))
    .unwrap_or_else(|_| SdsHttpBytes::empty())
}

/// # Safety
/// If `len > 0`, `data` must point to `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn sds_http_base64_decode(data: *const u8, len: usize) -> SdsHttpBytes {
    catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { bytes_slice(data, len) };
        SdsHttpBytes::from_vec(base64_decode(slice))
    }))
    .unwrap_or_else(|_| SdsHttpBytes::empty())
}

/// # Safety
/// If `len > 0`, `data` must point to `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn sds_http_percent_encode(data: *const u8, len: usize) -> SdsHttpBytes {
    catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { bytes_slice(data, len) };
        SdsHttpBytes::from_vec(percent_encode_bytes(slice))
    }))
    .unwrap_or_else(|_| SdsHttpBytes::empty())
}

/// # Safety
/// If `len > 0`, `data` must point to `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn sds_http_percent_decode(data: *const u8, len: usize) -> SdsHttpBytes {
    catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { bytes_slice(data, len) };
        SdsHttpBytes::from_vec(percent_decode_bytes(slice))
    }))
    .unwrap_or_else(|_| SdsHttpBytes::empty())
}

/// # Safety
/// If `len > 0`, `data` must point to `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn sds_http_parse_query_string(
    data: *const u8,
    len: usize,
) -> SdsHttpHeaderVec {
    catch_unwind(AssertUnwindSafe(|| {
        let slice = unsafe { bytes_slice(data, len) };
        let parsed = parse_query_string(slice);
        let owned: Vec<SdsHttpHeaderOwned> = parsed
            .into_iter()
            .map(|(k, v)| SdsHttpHeaderOwned {
                name: SdsHttpBytes::from_vec(k),
                value: SdsHttpBytes::from_vec(v),
            })
            .collect();
        SdsHttpHeaderVec::from_vec(owned)
    }))
    .unwrap_or_else(|_| SdsHttpHeaderVec::empty())
}

/// # Safety
/// `config`, `callbacks` (plus non-null C string fields), and `out_error` must be valid pointers.
/// `callbacks->user_data` and callback pointers must remain thread-safe until after
/// `sds_http_server_destroy` completes.
#[no_mangle]
pub unsafe extern "C" fn sds_http_server_create(
    config: *const SdsHttpServerConfig,
    callbacks: *const SdsHttpServerCallbacks,
    out_error: *mut SdsHttpBytes,
) -> *mut HttpServerInstance {
    catch_unwind(AssertUnwindSafe(|| {
        if config.is_null() || callbacks.is_null() {
            unsafe { write_out_error(out_error, "null server config or callbacks".into()) };
            return std::ptr::null_mut();
        }
        let cfg = unsafe { &*config };
        let cbs = unsafe { &*callbacks };

        let (Some(create_connection), Some(drop_connection), Some(create_request), Some(drop_request), Some(attach_request_body), Some(dispatch_request)) = (
            cbs.create_connection,
            cbs.drop_connection,
            cbs.create_request,
            cbs.drop_request,
            cbs.attach_request_body,
            cbs.dispatch_request,
        ) else {
            unsafe { write_out_error(out_error, "missing required server callback".into()) };
            return std::ptr::null_mut();
        };

        let settings = ServerSettings {
            port: cfg.port,
            thread_pool_size: cfg.thread_pool_size,
            timeout_request_secs: cfg.timeout_request_secs,
            timeout_content_secs: cfg.timeout_content_secs,
            max_request_streambuf_size: cfg.max_request_streambuf_size,
            max_request_header_size: cfg.max_request_header_size,
            address: unsafe { cstr_to_string(cfg.address) },
            reuse_address: cfg.reuse_address,
            is_https: cfg.is_https,
            cert_file: unsafe { cstr_to_opt_nonempty(cfg.cert_file) },
            key_file: unsafe { cstr_to_opt_nonempty(cfg.key_file) },
            verify_file: unsafe { cstr_to_opt_nonempty(cfg.verify_file) },
            require_client_cert: cfg.require_client_cert,
        };

        let srv_callbacks = ServerCallbacks {
            user_data: cbs.user_data as usize,
            on_bound: cbs.on_bound,
            create_connection,
            drop_connection,
            on_connection_accepted: cbs.on_connection_accepted,
            on_verify_client: cbs.on_verify_client,
            on_verify_failed: cbs.on_verify_failed,
            on_connection_authenticated: cbs.on_connection_authenticated,
            create_request,
            drop_request,
            on_request_header: cbs.on_request_header,
            attach_request_body,
            dispatch_request,
            on_error: cbs.on_error,
        };

        match HttpServerInstance::create(settings, srv_callbacks) {
            Ok(srv) => Box::into_raw(Box::new(srv)),
            Err(err) => {
                unsafe { write_out_error(out_error, err) };
                std::ptr::null_mut()
            }
        }
    }))
    .unwrap_or_else(|_| {
        unsafe { write_out_error(out_error, "panic inside sds_http_server_create".into()) };
        std::ptr::null_mut()
    })
}

/// # Safety
/// `server` must be a valid pointer from `sds_http_server_create` not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn sds_http_server_start(
    server: *mut HttpServerInstance,
    out_error: *mut SdsHttpBytes,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if server.is_null() {
            unsafe { write_out_error(out_error, "null server pointer".into()) };
            return false;
        }
        let srv = unsafe { &*server };
        match srv.run() {
            Ok(()) => true,
            Err(err) => {
                unsafe { write_out_error(out_error, err) };
                false
            }
        }
    }))
    .unwrap_or_else(|_| {
        unsafe { write_out_error(out_error, "panic inside sds_http_server_start".into()) };
        false
    })
}

/// # Safety
/// `server` must be null or a valid pointer from `sds_http_server_create` not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn sds_http_server_stop(server: *mut HttpServerInstance) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !server.is_null() {
            unsafe { (&*server).stop() };
        }
    }));
}

/// # Safety
/// `server` must be null or a valid pointer from `sds_http_server_create` with no concurrent calls.
#[no_mangle]
pub unsafe extern "C" fn sds_http_server_destroy(server: *mut HttpServerInstance) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !server.is_null() {
            unsafe { drop(Box::from_raw(server)) };
        }
    }));
}

/// # Safety
/// `sender` must be an unconsumed handle passed to a callback; `data` must cover `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn sds_http_response_send(
    sender: *mut ResponseSenderHandle,
    data: *const u8,
    len: usize,
    close_connection: bool,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !sender.is_null() {
            let handle = unsafe { Box::from_raw(sender) };
            let bytes = unsafe { bytes_slice(data, len) }.to_vec();
            handle.send(bytes, close_connection);
        }
    }));
}

/// # Safety
/// `sender` must be null or an unconsumed handle passed to a callback.
#[no_mangle]
pub unsafe extern "C" fn sds_http_response_abort(sender: *mut ResponseSenderHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !sender.is_null() {
            let handle = unsafe { Box::from_raw(sender) };
            handle.abort();
        }
    }));
}

/// # Safety
/// `config` (plus non-null C string fields) and `out_error` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sds_http_client_create(
    config: *const SdsHttpClientConfig,
    out_error: *mut SdsHttpBytes,
) -> *mut HttpClientInstance {
    catch_unwind(AssertUnwindSafe(|| {
        if config.is_null() {
            unsafe { write_out_error(out_error, "null client config".into()) };
            return std::ptr::null_mut();
        }
        let cfg = unsafe { &*config };
        let settings = ClientSettings {
            host: unsafe { cstr_to_string(cfg.host) },
            port: cfg.port,
            default_port: cfg.default_port,
            is_https: cfg.is_https,
            verify_certificate: cfg.verify_certificate,
            cert_file: unsafe { cstr_to_opt_nonempty(cfg.cert_file) },
            key_file: unsafe { cstr_to_opt_nonempty(cfg.key_file) },
            verify_file: unsafe { cstr_to_opt_nonempty(cfg.verify_file) },
        };
        match HttpClientInstance::create(settings) {
            Ok(cli) => Box::into_raw(Box::new(cli)),
            Err(err) => {
                unsafe { write_out_error(out_error, err) };
                std::ptr::null_mut()
            }
        }
    }))
    .unwrap_or_else(|_| {
        unsafe { write_out_error(out_error, "panic inside sds_http_client_create".into()) };
        std::ptr::null_mut()
    })
}

/// # Safety
/// `client` must be null or a valid pointer from `sds_http_client_create` not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn sds_http_client_stop(client: *mut HttpClientInstance) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !client.is_null() {
            unsafe { (&*client).stop() };
        }
    }));
}

/// # Safety
/// `client` must be null or a valid pointer from `sds_http_client_create` with no active requests.
#[no_mangle]
pub unsafe extern "C" fn sds_http_client_destroy(client: *mut HttpClientInstance) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !client.is_null() {
            unsafe { drop(Box::from_raw(client)) };
        }
    }));
}

/// # Safety
/// `client` must remain valid and undestroyed for the duration of the call; all input byte slices
/// must point to valid memory for their stated lengths.
#[no_mangle]
pub unsafe extern "C" fn sds_http_client_request(
    client: *mut HttpClientInstance,
    method: *const u8,
    method_len: usize,
    path: *const u8,
    path_len: usize,
    headers: *const HeaderSliceFfi,
    header_count: usize,
    body: *const u8,
    body_len: usize,
    timeout_secs: i64,
    timeout_connect_secs: i64,
    max_response_bytes: usize,
) -> SdsHttpClientResponse {
    catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return SdsHttpClientResponse::error(ErrorKind::Io, "null client pointer".into());
        }
        let cli = unsafe { &*client };
        let method_str =
            String::from_utf8_lossy(unsafe { bytes_slice(method, method_len) }).into_owned();
        let path_str =
            String::from_utf8_lossy(unsafe { bytes_slice(path, path_len) }).into_owned();

        let hdr_slices = if headers.is_null() || header_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(headers, header_count) }
        };
        let mut hdr_pairs = Vec::with_capacity(hdr_slices.len());
        for h in hdr_slices {
            let k = String::from_utf8_lossy(unsafe { bytes_slice(h.name, h.name_len) }).into_owned();
            let v =
                String::from_utf8_lossy(unsafe { bytes_slice(h.value, h.value_len) }).into_owned();
            hdr_pairs.push((k, v));
        }
        let body_slice = unsafe { bytes_slice(body, body_len) };

        match cli.request(
            &method_str,
            &path_str,
            &hdr_pairs,
            body_slice,
            timeout_secs,
            timeout_connect_secs,
            max_response_bytes,
        ) {
            Ok(resp) => {
                let owned_headers: Vec<SdsHttpHeaderOwned> = resp
                    .headers
                    .into_iter()
                    .map(|(k, v)| SdsHttpHeaderOwned {
                        name: SdsHttpBytes::from_string(k),
                        value: SdsHttpBytes::from_string(v),
                    })
                    .collect();
                SdsHttpClientResponse {
                    ok: true,
                    error_kind: ErrorKind::None,
                    error_message: SdsHttpBytes::empty(),
                    http_version: SdsHttpBytes::from_string(resp.http_version),
                    status_code: SdsHttpBytes::from_string(resp.status_code),
                    headers: SdsHttpHeaderVec::from_vec(owned_headers),
                    body: SdsHttpBytes::from_vec(resp.body),
                }
            }
            Err((kind, msg)) => SdsHttpClientResponse::error(kind, msg),
        }
    }))
    .unwrap_or_else(|_| {
        SdsHttpClientResponse::error(ErrorKind::Io, "panic inside sds_http_client_request".into())
    })
}

/// # Safety
/// `resp` must have been returned by `sds_http_client_request` and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn sds_http_client_response_free(resp: SdsHttpClientResponse) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        sds_http_bytes_free(resp.error_message);
        sds_http_bytes_free(resp.http_version);
        sds_http_bytes_free(resp.status_code);
        sds_http_header_vec_free(resp.headers);
        sds_http_bytes_free(resp.body);
    }));
}
