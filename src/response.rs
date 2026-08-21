use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Deserialize)]
pub struct Response {
    /// Final URL after any redirects. For the originally-requested URL
    /// see `request_url`.
    pub url: String,
    pub status: u16,
    // Vec, not HashMap — HTTP allows duplicate header names (e.g. Set-Cookie)
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing)]
    pub body_bytes: Vec<u8>,
    pub elapsed_ms: u64,
    pub redirect_chain: Vec<RedirectHop>,
    /// TLS certificate info extracted during handshake (None for plain HTTP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_info: Option<CertInfo>,
    /// IP address actually used for the final hop's TCP connection.
    /// `None` when the request went through a proxy (we see the proxy's IP,
    /// not the target's, and the target IP is resolved by the proxy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_ip: Option<String>,
    /// The URL the caller originally requested (before redirects).
    /// `url` reflects the final URL after redirects; this preserves
    /// the request side for logging / httpx-style `.request.url`.
    pub request_url: String,
    /// HTTP method of the original request (e.g. `"GET"`, `"POST"`).
    pub request_method: String,
    /// Debug messages collected during the request (for Python-side inspection)
    #[serde(skip_serializing)]
    pub debug_log: Vec<String>,
    /// Why `body_bytes` is not decoded content, when it isn't.
    ///
    /// `None` on any ordinary response, including one with no
    /// `Content-Encoding` at all. `Some(reason)` means the body is not what
    /// the header said it was, and the reason says how far decoding got.
    ///
    /// With nothing undone, `body_bytes` is exactly what arrived: an
    /// unsupported coding, or a body that doesn't match what it claims. With
    /// a stack only partly undone, it is as far in as decoding reached, which
    /// is usually the body, since a header that overstates the codings is
    /// more common than a body encoded that many times. And with a stream
    /// that decoded partway and then reported damage or an early end,
    /// `body_bytes` is that prefix. The last case is the one to be careful
    /// with: those bytes read like an ordinary body and aren't one.
    ///
    /// A response is worth keeping either way, since the status line and
    /// headers arrived cleanly and losing the response looks the same as an
    /// unreachable host. But anything that hashes, matches or diffs bodies
    /// has to be able to tell encoded bytes from content, which is what this
    /// is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_error: Option<String>,

    // ── Lazy-computed caches ──────────────────────────────────────
    // Each is filled on first access of the corresponding accessor
    // (`body()`, `raw_headers()`, `cookies()`, `hash()`) and never
    // recomputed. Skipped by serde — derivable from eager fields.
    // `pub(crate)` so other modules in the crate (mock, hyper) can
    // initialize them as empty when constructing a Response by
    // struct literal. External callers should use `Response::new`.
    #[serde(skip)]
    pub(crate) body_cache: OnceLock<String>,
    #[serde(skip)]
    pub(crate) raw_headers_cache: OnceLock<String>,
    #[serde(skip)]
    pub(crate) cookies_cache: OnceLock<HashMap<String, String>>,
    #[serde(skip)]
    pub(crate) hash_cache: OnceLock<ResponseHash>,
}

impl Serialize for Response {
    /// Custom Serialize so the lazy-computed fields (`body`,
    /// `raw_headers`, `cookies`, `hash`) appear in the JSON output.
    /// Serializing a Response forces them all to be computed —
    /// callers that just want lazy memory behavior should access
    /// fields directly instead of serializing.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut out = s.serialize_struct("Response", 13)?;
        out.serialize_field("url", &self.url)?;
        out.serialize_field("status", &self.status)?;
        out.serialize_field("headers", &self.headers)?;
        out.serialize_field("body", self.body())?;
        out.serialize_field("raw_headers", self.raw_headers())?;
        out.serialize_field("cookies", self.cookies())?;
        out.serialize_field("hash", self.hash())?;
        out.serialize_field("elapsed_ms", &self.elapsed_ms)?;
        out.serialize_field("redirect_chain", &self.redirect_chain)?;
        if let Some(ref c) = self.cert_info {
            out.serialize_field("cert_info", c)?;
        } else {
            out.skip_field("cert_info")?;
        }
        if let Some(ref p) = self.peer_ip {
            out.serialize_field("peer_ip", p)?;
        } else {
            out.skip_field("peer_ip")?;
        }
        out.serialize_field("request_url", &self.request_url)?;
        out.serialize_field("request_method", &self.request_method)?;
        if let Some(ref e) = self.decode_error {
            out.serialize_field("decode_error", e)?;
        } else {
            out.skip_field("decode_error")?;
        }
        out.end()
    }
}

impl Clone for Response {
    fn clone(&self) -> Self {
        // Lazy caches do not propagate across clones — the clone gets
        // empty caches and rebuilds on first access. Clones are rare
        // (only PyBatchResult.response getter), so the rebuild cost
        // doesn't matter and we avoid an Arc per cache field.
        Response {
            url: self.url.clone(),
            status: self.status,
            headers: self.headers.clone(),
            body_bytes: self.body_bytes.clone(),
            elapsed_ms: self.elapsed_ms,
            redirect_chain: self.redirect_chain.clone(),
            cert_info: self.cert_info.clone(),
            peer_ip: self.peer_ip.clone(),
            request_url: self.request_url.clone(),
            request_method: self.request_method.clone(),
            debug_log: self.debug_log.clone(),
            decode_error: self.decode_error.clone(),
            body_cache: OnceLock::new(),
            raw_headers_cache: OnceLock::new(),
            cookies_cache: OnceLock::new(),
            hash_cache: OnceLock::new(),
        }
    }
}

impl Response {
    /// `true` if the status is in the 2xx-3xx range. Matches the
    /// common convention (httpx, requests) for distinguishing
    /// "request completed without error" from a 4xx/5xx response.
    pub fn is_success(&self) -> bool {
        (200..400).contains(&self.status)
    }

    /// Body decoded as UTF-8 (lossy — invalid sequences become U+FFFD).
    /// Computed on first access and cached.
    pub fn body(&self) -> &str {
        self.body_cache
            .get_or_init(|| match std::str::from_utf8(&self.body_bytes) {
                Ok(s) => s.to_string(),
                Err(_) => String::from_utf8_lossy(&self.body_bytes).into_owned(),
            })
    }

    /// Canonical `Name: Value\r\nName: Value` form of `headers`. No
    /// trailing CRLF. This is the exact byte sequence input to
    /// `hash.header_*`. Computed on first access and cached.
    pub fn raw_headers(&self) -> &str {
        self.raw_headers_cache
            .get_or_init(|| build_raw_headers(&self.headers))
    }

    /// Cookies parsed from `Set-Cookie` headers, name → value. Only
    /// the `name=value` pair before the first `;` is kept (attributes
    /// like `Path`, `Expires`, `HttpOnly` are stripped). On duplicate
    /// names the last `Set-Cookie` wins. Computed on first access.
    pub fn cookies(&self) -> &HashMap<String, String> {
        self.cookies_cache
            .get_or_init(|| parse_set_cookies(&self.headers))
    }

    /// Body and header content hashes (md5, sha256, mmh3). Computed
    /// on first access and cached. Hashing a 10MB body is real work,
    /// so callers that don't need fingerprints don't pay for them.
    pub fn hash(&self) -> &ResponseHash {
        // Populate raw_headers cache first so the hash and the
        // exposed `raw_headers()` accessor share the same bytes.
        let raw = self.raw_headers();
        self.hash_cache
            .get_or_init(|| ResponseHash::compute(&self.body_bytes, raw))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub url: String,
    pub status: u16,
    /// IP actually used for this hop. Same caveats as `Response::peer_ip`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_ip: Option<String>,
}

/// TLS certificate information extracted during the handshake.
/// Matches what BBOT's sslcert module extracts — CN, SANs, emails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    /// Subject Common Name (CN)
    pub common_name: Option<String>,
    /// Subject Alternative Names (DNS entries)
    pub sans: Vec<String>,
    /// Email addresses from Subject and Issuer
    pub emails: Vec<String>,
    /// Issuer Common Name
    pub issuer: Option<String>,
    /// Not Before (ISO 8601 string)
    pub not_before: Option<String>,
    /// Not After (ISO 8601 string)
    pub not_after: Option<String>,
    /// SHA-256 fingerprint of the certificate (hex encoded)
    pub fingerprint_sha256: Option<String>,
}

/// Response content hashes matching BBOT's response_to_json format.
/// Computed in Rust so Python doesn't have to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseHash {
    pub body_md5: String,
    pub body_mmh3: i32,
    pub body_sha256: String,
    pub header_md5: String,
    pub header_mmh3: i32,
    pub header_sha256: String,
}

impl ResponseHash {
    /// Compute all six hashes from the body bytes and a pre-built
    /// `raw_headers` string. The raw header string is the canonical
    /// `Name: Value\r\nName: Value` form — same string surfaced on
    /// `Response::raw_headers`. Sharing it avoids the join+collect
    /// twice per response.
    pub fn compute(body: &[u8], raw_headers: &str) -> Self {
        let header_bytes = raw_headers.as_bytes();

        ResponseHash {
            body_md5: hex_digest(openssl::hash::MessageDigest::md5(), body),
            body_mmh3: mmh3_32(body),
            body_sha256: hex_digest(openssl::hash::MessageDigest::sha256(), body),
            header_md5: hex_digest(openssl::hash::MessageDigest::md5(), header_bytes),
            header_mmh3: mmh3_32(header_bytes),
            header_sha256: hex_digest(openssl::hash::MessageDigest::sha256(), header_bytes),
        }
    }
}

/// Format the canonical `Name: Value\r\nName: Value` string used for
/// `Response::raw_headers` and as input to `ResponseHash::compute`.
/// No trailing CRLF.
pub fn build_raw_headers(headers: &[(String, String)]) -> String {
    let mut out = String::new();
    let mut first = true;
    for (k, v) in headers {
        if !first {
            out.push_str("\r\n");
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        first = false;
    }
    out
}

/// Parse `Set-Cookie` headers into a name→value map. Only the part
/// before the first `;` is considered (attributes like `Path=`,
/// `Expires=`, `HttpOnly` are stripped). Duplicate names: last wins.
pub fn parse_set_cookies(headers: &[(String, String)]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        // Only the `name=value` pair before any `;`-delimited attribute.
        let pair = v.split(';').next().unwrap_or("");
        if let Some((name, value)) = pair.split_once('=') {
            out.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    out
}

/// Compute hex-encoded digest using OpenSSL (already linked)
fn hex_digest(algo: openssl::hash::MessageDigest, data: &[u8]) -> String {
    openssl::hash::hash(algo, data)
        .map(|digest| digest.iter().map(|b| format!("{:02x}", b)).collect())
        .unwrap_or_default()
}

/// MurmurHash3 32-bit, matching Python's mmh3.hash() (signed i32, seed=0)
fn mmh3_32(data: &[u8]) -> i32 {
    use std::io::Cursor;
    let mut reader = Cursor::new(data);
    // murmur3_32 returns u32 with seed; Python mmh3.hash returns signed i32
    let hash = murmur3::murmur3_32(&mut reader, 0).unwrap_or(0);
    hash as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_matches_python() {
        // Python: hashlib.md5(b"hello world").hexdigest()
        let result = hex_digest(openssl::hash::MessageDigest::md5(), b"hello world");
        assert_eq!(result, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_sha256_matches_python() {
        // Python: hashlib.sha256(b"hello world").hexdigest()
        let result = hex_digest(openssl::hash::MessageDigest::sha256(), b"hello world");
        assert_eq!(
            result,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_mmh3_matches_python() {
        // Python: mmh3.hash(b"hello world") -> 1586663183
        assert_eq!(mmh3_32(b"hello world"), 1586663183);
    }

    #[test]
    fn test_mmh3_empty_matches_python() {
        // Python: mmh3.hash(b"") -> 0
        assert_eq!(mmh3_32(b""), 0);
    }

    #[test]
    fn test_response_hash_body_hashes() {
        let hash = ResponseHash::compute(b"test body", "");
        assert!(!hash.body_md5.is_empty());
        assert!(!hash.body_sha256.is_empty());
        // Verify body hashes are for "test body"
        assert_eq!(
            hash.body_md5,
            hex_digest(openssl::hash::MessageDigest::md5(), b"test body")
        );
        assert_eq!(
            hash.body_sha256,
            hex_digest(openssl::hash::MessageDigest::sha256(), b"test body")
        );
        assert_eq!(hash.body_mmh3, mmh3_32(b"test body"));
    }

    #[test]
    fn test_response_hash_header_format() {
        // BBOT joins headers as "Name: Value\r\nName: Value"
        let headers = vec![
            ("content-type".to_string(), "text/html".to_string()),
            ("server".to_string(), "nginx".to_string()),
        ];
        let raw = build_raw_headers(&headers);
        let hash = ResponseHash::compute(b"", &raw);

        let expected_raw = "content-type: text/html\r\nserver: nginx";
        assert_eq!(raw, expected_raw);
        assert_eq!(
            hash.header_md5,
            hex_digest(openssl::hash::MessageDigest::md5(), expected_raw.as_bytes())
        );
        assert_eq!(
            hash.header_sha256,
            hex_digest(
                openssl::hash::MessageDigest::sha256(),
                expected_raw.as_bytes()
            )
        );
        assert_eq!(hash.header_mmh3, mmh3_32(expected_raw.as_bytes()));
    }

    #[test]
    fn test_build_raw_headers_empty() {
        assert_eq!(build_raw_headers(&[]), "");
    }

    #[test]
    fn test_build_raw_headers_single() {
        let h = vec![("X-Foo".to_string(), "bar".to_string())];
        assert_eq!(build_raw_headers(&h), "X-Foo: bar");
    }

    #[test]
    fn test_parse_set_cookies_single() {
        let headers = vec![(
            "Set-Cookie".to_string(),
            "session=abc123; Path=/; HttpOnly".to_string(),
        )];
        let cookies = parse_set_cookies(&headers);
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_parse_set_cookies_multiple() {
        let headers = vec![
            ("Set-Cookie".to_string(), "a=1; Path=/".to_string()),
            ("Set-Cookie".to_string(), "b=2".to_string()),
        ];
        let cookies = parse_set_cookies(&headers);
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies.get("a"), Some(&"1".to_string()));
        assert_eq!(cookies.get("b"), Some(&"2".to_string()));
    }

    #[test]
    fn test_parse_set_cookies_duplicate_last_wins() {
        let headers = vec![
            ("Set-Cookie".to_string(), "x=first".to_string()),
            ("Set-Cookie".to_string(), "x=second".to_string()),
        ];
        let cookies = parse_set_cookies(&headers);
        assert_eq!(cookies.get("x"), Some(&"second".to_string()));
    }

    #[test]
    fn test_parse_set_cookies_case_insensitive_header() {
        let headers = vec![("set-cookie".to_string(), "y=z".to_string())];
        let cookies = parse_set_cookies(&headers);
        assert_eq!(cookies.get("y"), Some(&"z".to_string()));
    }

    #[test]
    fn test_parse_set_cookies_strips_whitespace() {
        let headers = vec![("Set-Cookie".to_string(), "  k = v  ; Path=/".to_string())];
        let cookies = parse_set_cookies(&headers);
        assert_eq!(cookies.get("k"), Some(&"v".to_string()));
    }

    #[test]
    fn test_parse_set_cookies_malformed_no_equals() {
        // "broken" has no `=`, BBOT silently skips — match that.
        let headers = vec![("Set-Cookie".to_string(), "broken; Path=/".to_string())];
        let cookies = parse_set_cookies(&headers);
        assert!(cookies.is_empty());
    }

    #[test]
    fn test_parse_set_cookies_ignores_other_headers() {
        let headers = vec![
            (
                "Cookie".to_string(),
                "session=should-be-ignored".to_string(),
            ),
            ("Content-Type".to_string(), "text/html".to_string()),
        ];
        let cookies = parse_set_cookies(&headers);
        assert!(cookies.is_empty());
    }
}
