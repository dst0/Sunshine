use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use percent_encoding::{percent_decode, AsciiSet, NON_ALPHANUMERIC};

const UNRESERVED_QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

const MAX_HEADER_COUNT: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramingError {
    HeadersTooLarge,
    NonCanonicalHeader,
    InvalidRequestLine,
    MissingHost,
    DuplicateHost,
    InvalidHost,
    TooManyHeaders,
    TransferEncodingNotAllowed,
    DuplicateContentLength,
    InvalidContentLength,
    BodyTooLarge,
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeadersTooLarge => write!(f, "request headers exceed maximum size"),
            Self::NonCanonicalHeader => write!(f, "non-canonical HTTP request head"),
            Self::InvalidRequestLine => write!(f, "invalid HTTP request line"),
            Self::MissingHost => write!(f, "missing Host header in HTTP/1.1 request"),
            Self::DuplicateHost => write!(f, "duplicate Host header"),
            Self::InvalidHost => write!(f, "invalid Host header"),
            Self::TooManyHeaders => write!(f, "too many HTTP headers"),
            Self::TransferEncodingNotAllowed => write!(f, "Transfer-Encoding is not supported"),
            Self::DuplicateContentLength => write!(f, "duplicate Content-Length header"),
            Self::InvalidContentLength => write!(f, "invalid Content-Length header"),
            Self::BodyTooLarge => write!(f, "request body exceeds maximum size"),
        }
    }
}

impl std::error::Error for FramingError {}

#[derive(Debug, Clone)]
pub struct ParsedRequestHead {
    pub method: String,
    pub path: String,
    pub query_string: String,
    pub http_version: String,
    pub http_minor: u8,
    pub headers: Vec<(String, String)>,
    pub content_length: usize,
    pub close_after_response: bool,
}

#[inline]
pub fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[inline]
fn is_valid_field_value_byte(b: u8) -> bool {
    b == b'\t' || (b >= 0x20 && b != 0x7f)
}

/// Find the end of the HTTP head (`\r\n\r\n`) within `max_header_size`, rejecting NUL or bare CR/LF
/// as bytes arrive. Wait if the buffer ends with a single trailing `\r` that might be part of `\r\n`.
pub fn scan_head_end(buf: &[u8], max_header_size: usize) -> Result<Option<usize>, FramingError> {
    let check_len = buf.len().min(max_header_size);
    let slice = &buf[..check_len];
    let mut i = 0;
    while i < slice.len() {
        let b = slice[i];
        if b == 0 {
            return Err(FramingError::NonCanonicalHeader);
        }
        if b == b'\n' {
            // Every LF must be immediately preceded by CR.
            if i == 0 || slice[i - 1] != b'\r' {
                return Err(FramingError::NonCanonicalHeader);
            }
            // Check for \r\n\r\n ending at i + 1.
            if i >= 3 && &slice[i - 3..=i] == b"\r\n\r\n" {
                return Ok(Some(i + 1));
            }
        } else if b == b'\r' {
            if i + 1 < slice.len() {
                if slice[i + 1] != b'\n' {
                    return Err(FramingError::NonCanonicalHeader);
                }
            } else if buf.len() > max_header_size {
                return Err(FramingError::HeadersTooLarge);
            }
        }
        i += 1;
    }
    if buf.len() >= max_header_size {
        return Err(FramingError::HeadersTooLarge);
    }
    Ok(None)
}

/// Validate that a bounded raw HTTP request head uses canonical CRLF framing without
/// bare CR/LF/NUL, missing colons, invalid tchar field names, or obs-fold.
pub fn has_canonical_header_lines(raw: &[u8]) -> bool {
    let Some(req_end) = find_crlf(raw) else {
        return false;
    };
    let request_line = &raw[..req_end];
    if request_line.is_empty()
        || request_line.contains(&b'\n')
        || request_line.contains(&b'\r')
        || request_line.contains(&0)
    {
        return false;
    }

    let mut rest = &raw[req_end + 2..];
    while rest != b"\r\n" {
        let Some(line_end) = find_crlf(rest) else {
            return false;
        };
        if line_end == 0 {
            return false;
        }
        let line = &rest[..line_end];
        if line.contains(&0) || line.contains(&b'\r') || line.contains(&b'\n') {
            return false;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return false;
        };
        if colon == 0 {
            return false;
        }
        if !line[..colon].iter().all(|&b| is_tchar(b)) {
            return false;
        }
        rest = &rest[line_end + 2..];
    }
    true
}

#[inline]
fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|w| w == b"\r\n")
}

fn validate_headers_framing<'a, I>(
    headers: I,
    max_body_size: usize,
) -> Result<usize, FramingError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut content_length_count: usize = 0;
    let mut content_length_val: Option<&str> = None;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(FramingError::TransferEncodingNotAllowed);
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length_count += 1;
            if content_length_count > 1 {
                return Err(FramingError::DuplicateContentLength);
            }
            content_length_val = Some(value);
        }
    }

    let length = if let Some(val) = content_length_val {
        if val.is_empty() || !val.bytes().all(|b| b.is_ascii_digit()) {
            return Err(FramingError::InvalidContentLength);
        }
        val.parse::<usize>()
            .map_err(|_| FramingError::InvalidContentLength)?
    } else {
        0
    };

    if length > max_body_size {
        return Err(FramingError::BodyTooLarge);
    }

    Ok(length)
}

/// Validate request framing: canonical head lines, no Transfer-Encoding, at most one valid
/// decimal Content-Length within `max_body_size`.
pub fn validate_request_framing<'a, I>(
    raw_header: &[u8],
    headers: I,
    max_body_size: usize,
) -> Result<usize, FramingError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    if !has_canonical_header_lines(raw_header) {
        return Err(FramingError::NonCanonicalHeader);
    }
    validate_headers_framing(headers, max_body_size)
}

/// Strictly parse an HTTP/1.x request head ending with `\r\n\r\n`.
pub fn parse_request_head(
    raw_head: &[u8],
    max_body_size: usize,
) -> Result<ParsedRequestHead, FramingError> {
    if !has_canonical_header_lines(raw_head) {
        return Err(FramingError::NonCanonicalHeader);
    }

    // Strict RFC 9112 request-line syntax check: METHOD SP request-target SP HTTP/1.(0|1)
    let req_end = find_crlf(raw_head).ok_or(FramingError::NonCanonicalHeader)?;
    let req_line = &raw_head[..req_end];
    let first_sp = req_line
        .iter()
        .position(|&b| b == b' ')
        .ok_or(FramingError::InvalidRequestLine)?;
    let method_bytes = &req_line[..first_sp];
    if method_bytes.is_empty() || !method_bytes.iter().all(|&b| is_tchar(b)) {
        return Err(FramingError::InvalidRequestLine);
    }
    let after_method = &req_line[first_sp + 1..];
    let second_sp = after_method
        .iter()
        .position(|&b| b == b' ')
        .ok_or(FramingError::InvalidRequestLine)?;
    let target_bytes = &after_method[..second_sp];
    if target_bytes.is_empty()
        || target_bytes
            .iter()
            .any(|&b| b <= 0x20 || b == 0x7f || b == b' ')
    {
        return Err(FramingError::InvalidRequestLine);
    }
    let version_bytes = &after_method[second_sp + 1..];
    if version_bytes != b"HTTP/1.1" && version_bytes != b"HTTP/1.0" {
        return Err(FramingError::InvalidRequestLine);
    }

    // Count headers before passing slice to httparse so we handle up to MAX_HEADER_COUNT dynamically.
    let header_lines_count = raw_head[req_end + 2..]
        .windows(2)
        .filter(|w| *w == b"\r\n")
        .count()
        .saturating_sub(1);
    if header_lines_count > MAX_HEADER_COUNT {
        return Err(FramingError::TooManyHeaders);
    }

    let mut header_storage = vec![httparse::EMPTY_HEADER; header_lines_count.max(16)];
    let mut req = httparse::Request::new(&mut header_storage);
    let parsed_len = match req.parse(raw_head) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Err(FramingError::NonCanonicalHeader),
        Err(httparse::Error::TooManyHeaders) => return Err(FramingError::TooManyHeaders),
        Err(_) => return Err(FramingError::InvalidRequestLine),
    };
    if parsed_len != raw_head.len() {
        return Err(FramingError::NonCanonicalHeader);
    }

    let method = req
        .method
        .ok_or(FramingError::InvalidRequestLine)?
        .to_string();
    let raw_target = req.path.ok_or(FramingError::InvalidRequestLine)?;
    let (path, query_string) = match raw_target.find('?') {
        Some(idx) => (
            raw_target[..idx].to_string(),
            raw_target[idx + 1..].to_string(),
        ),
        None => (raw_target.to_string(), String::new()),
    };
    let (http_minor, http_version) = match req.version {
        Some(0) => (0u8, "1.0".to_string()),
        Some(1) => (1u8, "1.1".to_string()),
        _ => return Err(FramingError::InvalidRequestLine),
    };

    let mut headers = Vec::with_capacity(req.headers.len());
    let mut host_count: usize = 0;
    for h in req.headers.iter() {
        if h.name.is_empty() || !h.name.as_bytes().iter().all(|&b| is_tchar(b)) {
            return Err(FramingError::NonCanonicalHeader);
        }
        if !h.value.iter().all(|&b| is_valid_field_value_byte(b)) {
            return Err(FramingError::NonCanonicalHeader);
        }
        let val_str = std::str::from_utf8(h.value).map_err(|_| FramingError::NonCanonicalHeader)?;
        let trimmed = val_str.trim_matches(|c| c == ' ' || c == '\t');
        if h.name.eq_ignore_ascii_case("host") {
            host_count += 1;
            if host_count > 1 {
                return Err(FramingError::DuplicateHost);
            }
            if trimmed.bytes().any(|b| b <= 0x20 || b == 0x7f) {
                return Err(FramingError::InvalidHost);
            }
        }
        headers.push((h.name.to_string(), trimmed.to_string()));
    }
    if http_minor >= 1 && host_count == 0 {
        return Err(FramingError::MissingHost);
    }

    let content_length = validate_headers_framing(
        headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        max_body_size,
    )?;

    let mut conn_close = false;
    let mut conn_keep_alive = false;
    for (k, v) in &headers {
        if k.eq_ignore_ascii_case("connection") {
            for token in v.split(',') {
                let tok = token.trim();
                if tok.eq_ignore_ascii_case("close") {
                    conn_close = true;
                } else if tok.eq_ignore_ascii_case("keep-alive") {
                    conn_keep_alive = true;
                }
            }
        }
    }
    let close_after_response = if conn_close {
        true
    } else if conn_keep_alive {
        false
    } else {
        http_minor == 0
    };

    Ok(ParsedRequestHead {
        method,
        path,
        query_string,
        http_version,
        http_minor,
        headers,
        content_length,
        close_after_response,
    })
}

/// Ensure `Connection: close` is present (and `keep-alive` removed) in an HTTP/1.1 response
/// header block when closing after response. Uses move semantics for zero-copy fast paths.
pub fn inject_connection_close(raw: Vec<u8>) -> Vec<u8> {
    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return raw;
    };
    let head = &raw[..header_end];
    let mut has_close = false;
    let mut has_keep_alive = false;
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            if line[..colon]
                .trim_ascii()
                .eq_ignore_ascii_case(b"connection")
            {
                for token in line[colon + 1..].split(|&b| b == b',') {
                    let tok = token.trim_ascii();
                    if tok.eq_ignore_ascii_case(b"close") {
                        has_close = true;
                    } else if tok.eq_ignore_ascii_case(b"keep-alive") {
                        has_keep_alive = true;
                    }
                }
            }
        }
    }
    if has_close && !has_keep_alive {
        return raw;
    }

    let mut lines = head.split(|&b| b == b'\n');
    let status_line = lines.next().unwrap_or(b"");
    let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);
    let mut out = Vec::with_capacity(raw.len() + b"\r\nConnection: close".len());
    out.extend_from_slice(status_line);

    let mut preserved_tokens: Vec<&[u8]> = Vec::new();
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            if line[..colon]
                .trim_ascii()
                .eq_ignore_ascii_case(b"connection")
            {
                for token in line[colon + 1..].split(|&b| b == b',') {
                    let tok = token.trim_ascii();
                    if !tok.is_empty()
                        && !tok.eq_ignore_ascii_case(b"keep-alive")
                        && !tok.eq_ignore_ascii_case(b"close")
                    {
                        preserved_tokens.push(tok);
                    }
                }
                continue;
            }
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(line);
    }

    out.extend_from_slice(b"\r\nConnection: ");
    for tok in preserved_tokens {
        out.extend_from_slice(tok);
        out.extend_from_slice(b", ");
    }
    out.extend_from_slice(b"close");
    out.extend_from_slice(&raw[header_end..]);
    out
}

pub fn base64_encode(input: &[u8]) -> Vec<u8> {
    STANDARD.encode(input).into_bytes()
}

pub fn base64_decode(input: &[u8]) -> Vec<u8> {
    STANDARD.decode(input).unwrap_or_default()
}

/// Percent-encode raw arbitrary bytes without lossy UTF-8 replacement.
pub fn percent_encode_bytes(input: &[u8]) -> Vec<u8> {
    percent_encoding::percent_encode(input, UNRESERVED_QUERY_ENCODE_SET)
        .to_string()
        .into_bytes()
}

pub fn percent_decode_bytes(input: &[u8]) -> Vec<u8> {
    let replaced: Vec<u8> = input
        .iter()
        .map(|&b| if b == b'+' { b' ' } else { b })
        .collect();
    percent_decode(&replaced).collect()
}

pub fn parse_query_string(query: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    if query.is_empty() {
        return out;
    }
    for pair in query.split(|&b| b == b'&') {
        if pair.is_empty() {
            continue;
        }
        match pair.iter().position(|&b| b == b'=') {
            Some(eq) => {
                let name = &pair[..eq];
                if !name.is_empty() {
                    let val = percent_decode_bytes(&pair[eq + 1..]);
                    out.push((name.to_vec(), val));
                }
            }
            None => {
                out.push((pair.to_vec(), Vec::new()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_header_validation_matches_security_rules() {
        assert!(has_canonical_header_lines(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(b""));
        assert!(!has_canonical_header_lines(b"\r\nHost: localhost\r\n\r\n"));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\nHost: localhost\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\rHost: localhost\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET /\0 HTTP/1.1\r\nHost: localhost\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\r\nHost: localhost\nX-Test: 1\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\r\nHost: localhost\rX-Test: 1\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\r\nX-Test: a\0b\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\r\nMissingColon\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\r\n: value\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n folded\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\tfolded\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\r\nHost Name: localhost\r\n\r\n"
        ));
        assert!(!has_canonical_header_lines(
            b"GET / HTTP/1.1\r\nContent-Length : 1\r\n\r\n"
        ));
    }

    #[test]
    fn parse_request_head_rejects_smuggling_and_overflow() {
        let valid = b"POST /sds/v1/clipboard?type=text%2Fplain HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n";
        let parsed = parse_request_head(valid, 1024).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/sds/v1/clipboard");
        assert_eq!(parsed.query_string, "type=text%2Fplain");
        assert_eq!(parsed.content_length, 4);
        assert!(!parsed.close_after_response);

        assert_eq!(
            parse_request_head(
                b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
                1024
            )
            .unwrap_err(),
            FramingError::TransferEncodingNotAllowed
        );
        assert_eq!(
            parse_request_head(
                b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
                1024
            )
            .unwrap_err(),
            FramingError::DuplicateContentLength
        );
        assert_eq!(
            parse_request_head(
                b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: +1\r\n\r\n",
                1024
            )
            .unwrap_err(),
            FramingError::InvalidContentLength
        );
        assert_eq!(
            parse_request_head(
                b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 1x\r\n\r\n",
                1024
            )
            .unwrap_err(),
            FramingError::InvalidContentLength
        );
        assert_eq!(
            parse_request_head(
                b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2048\r\n\r\n",
                1024
            )
            .unwrap_err(),
            FramingError::BodyTooLarge
        );
    }

    #[test]
    fn scan_head_end_handles_split_crlf_and_rejects_early_bad_bytes() {
        assert_eq!(scan_head_end(b"GET / HTTP/1.1\r", 1024), Ok(None));
        assert_eq!(
            scan_head_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nbody", 1024),
            Ok(Some(27))
        );
        assert_eq!(
            scan_head_end(b"GET / HTTP/1.1\nHost: a\r\n\r\n", 1024),
            Err(FramingError::NonCanonicalHeader)
        );
        assert_eq!(
            scan_head_end(b"GET /\0 HTTP/1.1\r\n\r\n", 1024),
            Err(FramingError::NonCanonicalHeader)
        );
        assert_eq!(
            scan_head_end(b"GET / HTTP/1.1\r\nX-Pad: aaaaaaaaaa", 16),
            Err(FramingError::HeadersTooLarge)
        );
    }

    #[test]
    fn query_string_and_base64_round_trip() {
        let parsed = parse_query_string(b"type=text%2Fplain&msg=hello+world&empty=");
        assert_eq!(
            parsed,
            vec![
                (b"type".to_vec(), b"text/plain".to_vec()),
                (b"msg".to_vec(), b"hello world".to_vec()),
                (b"empty".to_vec(), b"".to_vec()),
            ]
        );
        assert_eq!(base64_encode(b"testuser:testpass"), b"dGVzdHVzZXI6dGVzdHBhc3M=");
        assert_eq!(base64_decode(b"dGVzdHVzZXI6dGVzdHBhc3M="), b"testuser:testpass");
        assert_eq!(base64_decode(b"%%%"), Vec::<u8>::new());
    }

    #[test]
    fn parse_request_head_enforces_host_header_and_version_rules() {
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\n\r\n", 1024).unwrap_err(),
            FramingError::MissingHost
        );
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 1024).unwrap_err(),
            FramingError::DuplicateHost
        );
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n", 1024).unwrap_err(),
            FramingError::InvalidHost
        );
        let http10 = parse_request_head(b"GET / HTTP/1.0\r\n\r\n", 1024).unwrap();
        assert_eq!(http10.http_minor, 0);
        assert!(http10.close_after_response);
    }

    #[test]
    fn inject_connection_close_handles_absent_close_and_keep_alive() {
        assert_eq!(
            inject_connection_close(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        );
        assert_eq!(
            inject_connection_close(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok".to_vec()),
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok"
        );
        assert_eq!(
            inject_connection_close(
                b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok"
                    .to_vec()
            ),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        );
        assert_eq!(
            inject_connection_close(
                b"HTTP/1.1 200 OK\r\nConnection: upgrade, keep-alive\r\n\r\n".to_vec()
            ),
            b"HTTP/1.1 200 OK\r\nConnection: upgrade, close\r\n\r\n"
        );
    }
}
