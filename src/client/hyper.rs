use super::{ClientError, HttpClient};
use crate::config::RequestConfig;
use crate::debug::{DebugLog, debug_record, new_debug_log};
use crate::response::{CertInfo, RedirectHop, Response};

use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::collections::HashMap;
use std::future::Future;
use std::io::Read;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Once};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

type FullBody = http_body_util::Full<bytes::Bytes>;

/// Percent-encode characters that are invalid in `http::Uri` but preserve
/// already-encoded `%XX` sequences and valid URI characters.
/// This makes blasthttp accept "messy" URLs that tools like httpx tolerate
/// (e.g. `<`, `>`, `{`, `}`, `|`, `^`, `` ` ``, spaces).
fn sanitize_uri(url: &str) -> String {
    // Minimally invasive: only percent-encode bytes that http::Uri actually
    // rejects (space, angle brackets, curly braces, control characters).
    // Everything else passes through as-is so offensive payloads like `\`
    // reach the server literally.
    fn must_encode(b: u8) -> bool {
        matches!(b, b' ' | b'"' | b'<' | b'>' | b'{' | b'}' | 0..=0x1F | 0x7F)
    }

    let bytes = url.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            // Already-encoded %XX — pass through unchanged
            out.push(bytes[i] as char);
            out.push(bytes[i + 1] as char);
            out.push(bytes[i + 2] as char);
            i += 3;
        } else if must_encode(b) {
            // Percent-encode this byte
            out.push_str(&format!("%{:02X}", b));
            i += 1;
        } else {
            out.push(b as char);
            i += 1;
        }
    }
    out
}

// Load the OpenSSL legacy provider once (for RC4, DES, etc.).
// The provider is statically compiled into libcrypto via `no-module` build flag.
// `Once` ensures this runs exactly once even across threads.
static INIT_LEGACY: Once = Once::new();

fn ensure_legacy_provider() {
    INIT_LEGACY.call_once(|| {
        let _default = openssl::provider::Provider::try_load(None, "default", true)
            .expect("failed to load OpenSSL default provider");
        let _legacy = openssl::provider::Provider::try_load(None, "legacy", true)
            .expect("failed to load OpenSSL legacy provider");
        // Leak the providers so they stay loaded for the process lifetime
        std::mem::forget(_default);
        std::mem::forget(_legacy);
    });
}

// ── TLS certificate extraction ────────────────────────────────────

/// Shared slot where the connector writes cert info during TLS handshake.
/// `send_inner` reads it after the response comes back.
type CertSlot = Arc<Mutex<Option<CertInfo>>>;

/// Shared map where the connector records the peer IP for every TCP
/// connection it opens, keyed on `"host:port"` (the authority of the
/// requested URI). `send_inner` looks the entry up after each redirect
/// hop so it can stamp the right IP on each `RedirectHop`. The map
/// only grows — pooled-connection reuse re-reads the existing entry,
/// new connections to the same host overwrite it (DNS round-robin
/// will lag, but the value will always be an IP that *was* used).
type PeerSlot = Arc<Mutex<HashMap<String, IpAddr>>>;

/// Build the lookup key for `PeerSlot` from a URI's host and port.
/// HTTPS defaults to 443, everything else to 80 — matches what
/// `HttpConnector` uses when it dials the OS resolver.
fn peer_slot_key(uri: &http::Uri) -> Option<String> {
    let host = uri.host()?;
    let default_port = if uri.scheme_str() == Some("https") {
        443
    } else {
        80
    };
    let port = uri.port_u16().unwrap_or(default_port);
    Some(format!("{}:{}", host, port))
}

fn extract_cert_info(ssl: &openssl::ssl::SslRef) -> Option<CertInfo> {
    let cert = ssl.peer_certificate()?;

    // Common Name from Subject
    let common_name = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().to_string().ok());

    // Subject Alternative Names (DNS entries)
    let sans = cert
        .subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.dnsname().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Email addresses from Subject and Issuer
    let mut emails: Vec<String> = Vec::new();
    for entry in cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::PKCS9_EMAILADDRESS)
    {
        if let Ok(s) = entry.data().to_string() {
            emails.push(s);
        }
    }
    for entry in cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::PKCS9_EMAILADDRESS)
    {
        if let Ok(s) = entry.data().to_string()
            && !emails.contains(&s)
        {
            emails.push(s);
        }
    }
    // Also check SANs for email addresses
    if let Some(names) = cert.subject_alt_names() {
        for name in &names {
            if let Some(email) = name.email() {
                let email = email.to_string();
                if !emails.contains(&email) {
                    emails.push(email);
                }
            }
        }
    }

    // Issuer Common Name
    let issuer = cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().to_string().ok());

    // Validity dates (ASN1 time -> string)
    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    // SHA-256 fingerprint
    let fingerprint_sha256 = cert
        .digest(openssl::hash::MessageDigest::sha256())
        .ok()
        .map(|digest| {
            digest
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":")
        });

    Some(CertInfo {
        common_name,
        sans,
        emails,
        issuer,
        not_before: Some(not_before),
        not_after: Some(not_after),
        fingerprint_sha256,
    })
}

// ── OpenSSL connector ─────────────────────────────────────────────

// Custom HTTPS connector using OpenSSL directly.
// Wraps HttpConnector with TLS handshake via openssl + tokio-openssl.
#[derive(Clone)]
struct OpenSslConnector {
    http: HttpConnector,
    ssl: openssl::ssl::SslConnector,
    // Shared slot for cert info — written during handshake, read after response
    cert_slot: CertSlot,
    // Shared map of peer IPs — written when a fresh TCP connection is
    // opened, read after each redirect hop so the right IP gets stamped
    // on the `RedirectHop` (or final `Response`).
    peer_slot: PeerSlot,
    connect_timeout: Duration,
}

/// Encode a list of ALPN protocol names into the wire format OpenSSL
/// expects: each protocol prefixed with its length as a single byte,
/// then the name bytes, concatenated. e.g. ["h2", "http/1.1"] ->
/// b"\x02h2\x08http/1.1". Returns an error if any protocol name is
/// empty or longer than 255 bytes (ALPN length prefix is 1 byte).
fn encode_alpn_protocols(protos: &[String]) -> Result<Vec<u8>, ClientError> {
    let mut out = Vec::new();
    for p in protos {
        let bytes = p.as_bytes();
        if bytes.is_empty() {
            return Err(ClientError::tls(
                "ALPN protocol name cannot be empty".to_string(),
            ));
        }
        if bytes.len() > 255 {
            return Err(ClientError::tls(format!(
                "ALPN protocol name too long ({}B > 255): {}",
                bytes.len(),
                p
            )));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

fn parse_tls_version(s: &str) -> Result<openssl::ssl::SslVersion, ClientError> {
    match s.to_lowercase().as_str() {
        "1.0" | "tls1.0" | "tlsv1.0" => Ok(openssl::ssl::SslVersion::TLS1),
        "1.1" | "tls1.1" | "tlsv1.1" => Ok(openssl::ssl::SslVersion::TLS1_1),
        "1.2" | "tls1.2" | "tlsv1.2" => Ok(openssl::ssl::SslVersion::TLS1_2),
        "1.3" | "tls1.3" | "tlsv1.3" => Ok(openssl::ssl::SslVersion::TLS1_3),
        _ => Err(ClientError::other(format!(
            "unknown TLS version '{}' (use 1.0, 1.1, 1.2, 1.3)",
            s
        ))),
    }
}

/// Load system CA certificates into an SSL builder.
///
/// OpenSSL's `set_default_verify_paths` looks at the OPENSSLDIR compiled into
/// the library, which may not match the system cert store (e.g. when OpenSSL
/// is vendored). This function checks `SSL_CERT_FILE` / `SSL_CERT_DIR` env
/// vars first, then probes well-known system paths.
fn load_system_ca_certs(
    builder: &mut openssl::ssl::SslConnectorBuilder,
) -> Result<(), ClientError> {
    use std::path::Path;

    static CA_FILE_PATHS: &[&str] = &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ];

    static CA_DIR_PATHS: &[&str] = &[
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
        "/system/etc/security/cacerts",
    ];

    let mut loaded = false;

    // SSL_CERT_FILE env var takes priority
    if let Ok(cert_file) = std::env::var("SSL_CERT_FILE")
        && Path::new(&cert_file).is_file()
    {
        builder.set_ca_file(&cert_file).map_err(|e| {
            ClientError::tls(format!("failed to load CA file '{}': {}", cert_file, e))
        })?;
        loaded = true;
    }

    if !loaded {
        for path in CA_FILE_PATHS {
            if Path::new(path).is_file() && builder.set_ca_file(path).is_ok() {
                loaded = true;
                break;
            }
        }
    }

    // Also try SSL_CERT_DIR / well-known cert directories
    if let Ok(cert_dir) = std::env::var("SSL_CERT_DIR") {
        if Path::new(&cert_dir).is_dir()
            && builder
                .load_verify_locations(None, Some(Path::new(&cert_dir)))
                .is_ok()
        {
            loaded = true;
        }
    } else {
        for path in CA_DIR_PATHS {
            let p = Path::new(path);
            if p.is_dir() && builder.load_verify_locations(None, Some(p)).is_ok() {
                loaded = true;
                break;
            }
        }
    }

    if !loaded {
        // Last resort: try the compiled-in OpenSSL defaults
        builder
            .set_default_verify_paths()
            .map_err(|e| ClientError::tls(format!("no system CA certificates found: {}", e)))?;
    }

    Ok(())
}

impl OpenSslConnector {
    fn new(
        config: &RequestConfig,
        cert_slot: CertSlot,
        peer_slot: PeerSlot,
    ) -> Result<Self, ClientError> {
        // Ensure legacy ciphers (RC4, DES, etc.) are available
        ensure_legacy_provider();

        let mut builder =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())
                .map_err(|e| ClientError::tls(format!("SSL setup failed: {}", e)))?;

        // Security level 0: allow all ciphers including RC4, DES, export.
        // This is an offensive-first tool — we need to connect to anything.
        builder.set_security_level(0);

        if !config.should_verify_certs() {
            builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
        } else {
            load_system_ca_certs(&mut builder)?;
        }

        if let Some(ref ciphers) = config.cipher_string {
            builder.set_cipher_list(ciphers).map_err(|e| {
                ClientError::tls(format!("invalid cipher string '{}': {}", ciphers, e))
            })?;
        }

        if let Some(ref min_ver) = config.min_tls_version {
            let version = parse_tls_version(min_ver)?;
            builder
                .set_min_proto_version(Some(version))
                .map_err(|e| ClientError::tls(format!("failed to set min TLS version: {}", e)))?;
        }

        if let Some(ref max_ver) = config.max_tls_version {
            let version = parse_tls_version(max_ver)?;
            builder
                .set_max_proto_version(Some(version))
                .map_err(|e| ClientError::tls(format!("failed to set max TLS version: {}", e)))?;
        }

        // ALPN: advertise HTTP/2 and HTTP/1.1 support during TLS handshake.
        // The wire format is length-prefixed: [2, b'h', b'2', 8, b'h', b't', ...].
        //
        // An explicit `alpn_protocols` wins, which is the escape hatch for a
        // server that answers correctly over one protocol but not the other.
        // For instance one that puts a connection-specific header in an
        // HTTP/2 response, which RFC 9113 8.2.2 forbids and hyper treats as
        // fatal.
        // Requests offering different lists don't share a pooled connection:
        // `TlsKey` includes `alpn_protocols`.
        let alpn_wire: Vec<u8> = match &config.alpn_protocols {
            Some(protos) => encode_alpn_protocols(protos)?,
            None => b"\x02h2\x08http/1.1".to_vec(),
        };
        builder
            .set_alpn_protos(&alpn_wire)
            .map_err(|e| ClientError::tls(format!("failed to set ALPN: {}", e)))?;

        let ssl = builder.build();
        let connect_timeout = Duration::from_secs(config.timeout());
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(connect_timeout));

        Ok(OpenSslConnector {
            http,
            ssl,
            cert_slot,
            peer_slot,
            connect_timeout,
        })
    }
}

// hyper-util's Client needs a Service<Uri> that returns an async connection.
// We implement this by connecting TCP first, then optionally layering TLS on top.
// ConnectionStream is an enum that handles both plain HTTP and HTTPS connections.
enum ConnectionStream {
    Plain(tokio::net::TcpStream),
    Tls {
        stream: tokio_openssl::SslStream<tokio::net::TcpStream>,
        alpn_h2: bool,
    },
}

impl hyper::rt::Read for ConnectionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Plain(tcp) => {
                let mut io = hyper_util::rt::TokioIo::new(tcp);
                Pin::new(&mut io).poll_read(cx, buf)
            }
            ConnectionStream::Tls { stream, .. } => {
                let mut io = hyper_util::rt::TokioIo::new(stream);
                Pin::new(&mut io).poll_read(cx, buf)
            }
        }
    }
}

impl hyper::rt::Write for ConnectionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            ConnectionStream::Plain(tcp) => {
                let mut io = hyper_util::rt::TokioIo::new(tcp);
                Pin::new(&mut io).poll_write(cx, buf)
            }
            ConnectionStream::Tls { stream, .. } => {
                let mut io = hyper_util::rt::TokioIo::new(stream);
                Pin::new(&mut io).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Plain(tcp) => {
                let mut io = hyper_util::rt::TokioIo::new(tcp);
                Pin::new(&mut io).poll_flush(cx)
            }
            ConnectionStream::Tls { stream, .. } => {
                let mut io = hyper_util::rt::TokioIo::new(stream);
                Pin::new(&mut io).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Plain(tcp) => {
                let mut io = hyper_util::rt::TokioIo::new(tcp);
                Pin::new(&mut io).poll_shutdown(cx)
            }
            ConnectionStream::Tls { stream, .. } => {
                let mut io = hyper_util::rt::TokioIo::new(stream);
                Pin::new(&mut io).poll_shutdown(cx)
            }
        }
    }
}

impl hyper_util::client::legacy::connect::Connection for ConnectionStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        let mut connected = hyper_util::client::legacy::connect::Connected::new();
        if let ConnectionStream::Tls { alpn_h2: true, .. } = self {
            connected = connected.negotiated_h2();
        }
        connected
    }
}

impl Unpin for ConnectionStream {}

impl tower_service::Service<http::Uri> for OpenSslConnector {
    type Response = ConnectionStream;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(|e| Box::new(e) as _)
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let host = uri.host().unwrap_or("").to_string();
        let is_https = uri.scheme_str() == Some("https");
        // Compute the slot key from the original URI before we hand it
        // off to hyper's HttpConnector — that's the authority callers
        // will look up by.
        let slot_key = peer_slot_key(&uri);
        let http_fut = self.http.call(uri);
        let ssl_connector = self.ssl.clone();
        let cert_slot = self.cert_slot.clone();
        let peer_slot = self.peer_slot.clone();
        let connect_timeout = self.connect_timeout;

        Box::pin(async move {
            let tcp = http_fut.await?;
            let tcp_stream = tcp.into_inner();

            // Record peer IP for this fresh connection. Best-effort —
            // failure to read peer_addr (vanishingly rare) is not fatal.
            if let (Some(key), Ok(peer)) = (slot_key, tcp_stream.peer_addr())
                && let Ok(mut map) = peer_slot.lock()
            {
                map.insert(key, peer.ip());
            }

            // Plain HTTP — return raw TCP stream, no TLS handshake
            if !is_https {
                return Ok(ConnectionStream::Plain(tcp_stream));
            }

            let mut ssl_conf = openssl::ssl::Ssl::new(ssl_connector.context())
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            // Only set SNI for hostnames, not IP addresses (SNI with IPs is invalid per RFC)
            if host.parse::<std::net::IpAddr>().is_err() {
                ssl_conf
                    .set_hostname(&host)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            }
            // Hostname verification: when verify mode is PEER, pin the
            // expected identity so OpenSSL checks the cert's SAN/CN.
            if ssl_conf.verify_mode() != openssl::ssl::SslVerifyMode::NONE {
                let param = ssl_conf.param_mut();
                match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => param
                        .set_ip(ip)
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?,
                    Err(_) => param
                        .set_host(&host)
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?,
                }
            }

            let mut stream = tokio_openssl::SslStream::new(ssl_conf, tcp_stream)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            tokio::time::timeout(connect_timeout, Pin::new(&mut stream).connect())
                .await
                .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "TLS handshake with {} timed out after {}s",
                            host,
                            connect_timeout.as_secs()
                        ),
                    ))
                })?
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            // Extract cert info after successful handshake
            let cert_info = extract_cert_info(stream.ssl());
            if let Ok(mut slot) = cert_slot.lock() {
                *slot = cert_info;
            }

            // Check if HTTP/2 was negotiated via ALPN
            let alpn_h2 = stream.ssl().selected_alpn_protocol() == Some(b"h2");

            Ok(ConnectionStream::Tls { stream, alpn_h2 })
        })
    }
}

// ── Client types and pooling ──────────────────────────────────────
//
// HTTP proxy modes:
// - Forward proxy (HTTP targets): connect to proxy, send absolute-form URI
//   `GET http://target/path HTTP/1.1`. Uses raw http1::SendRequest to bypass
//   hyper Client's URI normalization (which strips scheme+authority).
// - CONNECT tunnel (HTTPS targets): proxy opens a raw TCP tunnel via CONNECT.
//   Uses hyper_util's Tunnel connector.
// - SOCKS5: works for both HTTP and HTTPS targets.

type DirectClient = Client<OpenSslConnector, FullBody>;
type TunnelProxyClient =
    Client<hyper_util::client::legacy::connect::proxy::Tunnel<OpenSslConnector>, FullBody>;
type Socks5ProxyClient =
    Client<hyper_util::client::legacy::connect::proxy::SocksV5<OpenSslConnector>, FullBody>;

/// The cached hyper client + its cert info slot.
/// hyper's Client uses Arc internally, so Clone shares the connection pool.
#[derive(Clone)]
struct CachedClient {
    inner: AnyClient,
    cert_slot: CertSlot,
    peer_slot: PeerSlot,
}

#[derive(Clone)]
enum AnyClient {
    Direct(DirectClient),
    Tunnel(TunnelProxyClient),
    Socks5(Socks5ProxyClient),
}

/// TLS config fields that must be part of the client cache key.
/// Requests with different TLS settings must not share a cached client.
#[derive(Clone, Hash, Eq, PartialEq)]
struct TlsKey {
    verify_certs: bool,
    cipher_string: Option<String>,
    min_tls_version: Option<String>,
    max_tls_version: Option<String>,
    alpn_protocols: Option<Vec<String>>,
}

impl TlsKey {
    fn from_config(config: &RequestConfig) -> Self {
        TlsKey {
            verify_certs: config.should_verify_certs(),
            cipher_string: config.cipher_string.clone(),
            min_tls_version: config.min_tls_version.clone(),
            max_tls_version: config.max_tls_version.clone(),
            alpn_protocols: config.alpn_protocols.clone(),
        }
    }
}

/// Which connection mode to use for a given request.
#[derive(Clone, Hash, Eq, PartialEq)]
enum ConnMode {
    /// No proxy — connect directly to target.
    Direct(TlsKey),
    /// HTTP proxy + HTTP target — forward proxy (absolute-form URI to proxy).
    ForwardProxy(String),
    /// HTTP proxy + HTTPS target — CONNECT tunnel through proxy.
    Tunnel { proxy_url: String, tls: TlsKey },
    /// SOCKS5 proxy — works for both HTTP and HTTPS targets.
    Socks5 { proxy_url: String, tls: TlsKey },
}

pub struct HyperClient {
    // Clients cached by connection mode. A scan using an HTTP proxy may need
    // both a ForwardProxy client (for HTTP targets) and a Tunnel client (for
    // HTTPS targets), so we cache per-mode rather than a single client.
    cached: Mutex<std::collections::HashMap<ConnMode, CachedClient>>,
}

impl Default for HyperClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperClient {
    pub fn new() -> Self {
        HyperClient {
            cached: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Determine the connection mode for a given request config + target URI.
    fn conn_mode(config: &RequestConfig, target_uri: &http::Uri) -> Result<ConnMode, ClientError> {
        let tls = TlsKey::from_config(config);
        match config.effective_proxy(target_uri.host().unwrap_or("")) {
            None => Ok(ConnMode::Direct(tls)),
            Some(proxy_url) => {
                let proxy_uri: http::Uri =
                    proxy_url.parse().map_err(|e: http::uri::InvalidUri| {
                        ClientError::invalid_url(format!("invalid proxy URL: {}", e))
                    })?;
                let proxy_scheme = proxy_uri.scheme_str().unwrap_or("");
                match proxy_scheme {
                    "http" | "https" => {
                        // HTTP proxy: use forward proxy for HTTP targets, tunnel for HTTPS
                        let target_is_https = target_uri.scheme_str() == Some("https");
                        if target_is_https {
                            Ok(ConnMode::Tunnel {
                                proxy_url: proxy_url.to_string(),
                                tls,
                            })
                        } else {
                            Ok(ConnMode::ForwardProxy(proxy_url.to_string()))
                        }
                    }
                    "socks5" | "socks5h" => Ok(ConnMode::Socks5 {
                        proxy_url: proxy_url.to_string(),
                        tls,
                    }),
                    _ => Err(ClientError::other(format!(
                        "unsupported proxy scheme '{}' (use http, https, socks5)",
                        proxy_scheme
                    ))),
                }
            }
        }
    }

    /// Get or build a cached client for the given connection mode.
    fn get_or_build(
        &self,
        config: &RequestConfig,
        mode: &ConnMode,
    ) -> Result<CachedClient, ClientError> {
        let mut guard = self
            .cached
            .lock()
            .map_err(|_| ClientError::other("client lock poisoned".to_string()))?;

        if let Some(cached) = guard.get(mode) {
            return Ok(cached.clone());
        }

        let cert_slot: CertSlot = Arc::new(Mutex::new(None));
        let peer_slot: PeerSlot = Arc::new(Mutex::new(HashMap::new()));
        let connector = OpenSslConnector::new(config, cert_slot.clone(), peer_slot.clone())?;
        let builder = Client::builder(TokioExecutor::new());

        let inner = match mode {
            ConnMode::Direct(_) => AnyClient::Direct(builder.build(connector)),
            ConnMode::ForwardProxy(_) => {
                // Forward proxy doesn't use a cached hyper Client — it dispatches
                // directly via http1::SendRequest in send_inner. This branch should
                // never be reached.
                unreachable!("ForwardProxy uses dispatch_forward_proxy, not get_or_build")
            }
            ConnMode::Tunnel { proxy_url, .. } => {
                let proxy_uri: http::Uri =
                    proxy_url.parse().map_err(|e: http::uri::InvalidUri| {
                        ClientError::invalid_url(format!("invalid proxy URL: {}", e))
                    })?;
                use hyper_util::client::legacy::connect::proxy::Tunnel;
                let tunnel = Tunnel::new(proxy_uri, connector);
                AnyClient::Tunnel(builder.build(tunnel))
            }
            ConnMode::Socks5 { proxy_url, .. } => {
                let proxy_uri: http::Uri =
                    proxy_url.parse().map_err(|e: http::uri::InvalidUri| {
                        ClientError::invalid_url(format!("invalid proxy URL: {}", e))
                    })?;
                use hyper_util::client::legacy::connect::proxy::SocksV5;
                let socks = SocksV5::new(proxy_uri, connector);
                AnyClient::Socks5(builder.build(socks))
            }
        };

        let cached = CachedClient {
            inner,
            cert_slot,
            peer_slot,
        };
        guard.insert(mode.clone(), cached.clone());
        Ok(cached)
    }
}

// ── Request dispatch ──────────────────────────────────────────────

async fn dispatch_request(
    client: &AnyClient,
    uri: &http::Uri,
    config: &RequestConfig,
    log: &DebugLog,
    redirect_cookies: Option<&str>,
) -> Result<SingleResponse, ClientError> {
    // The pooled high-level client populates Host / :authority from the URI
    // itself, so we don't add a Host header here. Adding it would cause
    // duplicate :authority + host in the HTTP/2 HPACK block.
    let request = build_request(uri, config, false, false, redirect_cookies)?;
    let v = config.verbosity;

    debug_record(log, v, 1, "   Request headers:");
    for (name, value) in request.headers() {
        debug_record(
            log,
            v,
            1,
            &format!("     {}: {}", name, value.to_str().unwrap_or("<binary>")),
        );
    }
    debug_record(log, v, 1, "   Sending request...");

    let hyper_response = match client {
        AnyClient::Direct(c) => c.request(request).await,
        AnyClient::Tunnel(c) => c.request(request).await,
        AnyClient::Socks5(c) => c.request(request).await,
    }
    .map_err(|e| {
        let msg = format!("request failed: {}", e);
        let err_str = e.to_string().to_lowercase();
        if err_str.contains("ssl") || err_str.contains("tls") || err_str.contains("certificate") {
            ClientError::tls(msg)
        } else {
            ClientError::connection(msg)
        }
    })?;

    parse_response(hyper_response, config, log).await
}

/// Opens a fresh TCP connection (optionally to a resolved IP instead of DNS)
/// and performs TLS if HTTPS (with SNI set to the original hostname).
/// Returns the connected stream and any certificate info collected during
/// the TLS handshake.
///
/// Shared setup used by `dispatch_direct` (one-shot hyper requests over an
/// un-pooled socket) and by callers that need a long-lived, unframed handle
/// to a TCP or TLS stream.
pub(crate) async fn connect_stream(
    target_uri: &http::Uri,
    config: &RequestConfig,
    log: &DebugLog,
) -> Result<
    (
        Box<dyn IoReadWrite + Send + Unpin>,
        Option<CertInfo>,
        Option<String>,
        Option<IpAddr>,
    ),
    ClientError,
> {
    use super::proxy::{self, ProxyScheme};

    config.validate_proxy().map_err(ClientError::other)?;

    let v = config.verbosity;
    let host = target_uri.host().unwrap_or("").to_string();
    let is_https = target_uri.scheme_str() == Some("https");
    let default_port = if is_https { 443 } else { 80 };
    let port = target_uri.port_u16().unwrap_or(default_port);

    // Decide initial hop. If a proxy is set, connect to the proxy first and
    // tunnel from there. resolve_ip is ignored when a proxy is set — DNS
    // resolution happens at the proxy for SOCKS5, and CONNECT addresses the
    // target by hostname.
    let proxy_config = match config.effective_proxy(&host) {
        Some(p) => Some(proxy::parse_proxy_url(p)?),
        None => None,
    };

    let connect_addr = match &proxy_config {
        Some(p) => format!("{}:{}", p.host, p.port),
        None => match config.resolve_ip.as_ref() {
            Some(ip) => format!("{}:{}", ip, port),
            None => format!("{}:{}", host, port),
        },
    };

    debug_record(
        log,
        v,
        1,
        &format!(
            "   connect_stream: connecting to {} (target={}:{}{})",
            connect_addr,
            host,
            port,
            if proxy_config.is_some() {
                " via proxy"
            } else {
                ""
            }
        ),
    );

    let connect_timeout = Duration::from_secs(config.timeout());
    let mut tcp = tokio::time::timeout(
        connect_timeout,
        tokio::net::TcpStream::connect(&connect_addr),
    )
    .await
    .map_err(|_| {
        ClientError::timeout(format!(
            "TCP connect to {} timed out after {}s",
            connect_addr,
            config.timeout()
        ))
    })?
    .map_err(|e| {
        ClientError::connection(format!("failed to connect to {}: {}", connect_addr, e))
    })?;

    // Capture peer IP for the target. When a proxy is in use, peer_addr
    // points at the proxy — useless to callers asking "what IP served
    // the request" — so report None for proxied connections. resolve_ip
    // is fine here: peer_addr will reflect whichever IP we forced.
    let peer_ip: Option<IpAddr> = if proxy_config.is_some() {
        None
    } else {
        tcp.peer_addr().ok().map(|a| a.ip())
    };

    // Disable Nagle on raw-path sockets. RawConnection callers send timing-
    // sensitive byte sequences (consecutive requests, split-then-flush
    // patterns) where Nagle's coalescing delay can cost the attack or let
    // cross-tenant traffic interleave on the server side. Non-fatal if the
    // OS refuses to set it.
    if let Err(e) = tcp.set_nodelay(true) {
        debug_record(
            log,
            v,
            1,
            &format!("   set_nodelay failed (non-fatal): {}", e),
        );
    }

    // Proxy handshake: open a byte-transparent tunnel to the target.
    if let Some(ref p) = proxy_config {
        match p.scheme {
            ProxyScheme::Http => {
                tokio::time::timeout(
                    connect_timeout,
                    proxy::perform_http_connect(&mut tcp, &host, port),
                )
                .await
                .map_err(|_| {
                    ClientError::timeout(format!(
                        "proxy CONNECT to {}:{} timed out after {}s",
                        host,
                        port,
                        config.timeout()
                    ))
                })??;
            }
            ProxyScheme::Socks5 => {
                tokio::time::timeout(
                    connect_timeout,
                    proxy::perform_socks5(
                        &mut tcp,
                        &host,
                        port,
                        p.username.as_deref(),
                        p.password.as_deref(),
                    ),
                )
                .await
                .map_err(|_| {
                    ClientError::timeout(format!(
                        "SOCKS5 handshake timed out after {}s",
                        config.timeout()
                    ))
                })??;
            }
        }
        debug_record(
            log,
            v,
            1,
            &format!("   proxy tunnel to {}:{} established", host, port),
        );
    }

    if !is_https {
        return Ok((Box::new(tcp), None, None, peer_ip));
    }

    ensure_legacy_provider();

    let mut ssl_builder =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())
            .map_err(|e| ClientError::tls(format!("SSL setup failed: {}", e)))?;

    ssl_builder.set_security_level(0);

    if !config.should_verify_certs() {
        ssl_builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
    } else {
        load_system_ca_certs(&mut ssl_builder)?;
    }
    if let Some(ref ciphers) = config.cipher_string {
        ssl_builder
            .set_cipher_list(ciphers)
            .map_err(|e| ClientError::tls(format!("invalid cipher string '{}': {}", ciphers, e)))?;
    }
    if let Some(ref min_ver) = config.min_tls_version {
        let version = parse_tls_version(min_ver)?;
        ssl_builder
            .set_min_proto_version(Some(version))
            .map_err(|e| ClientError::tls(format!("failed to set min TLS version: {}", e)))?;
    }
    if let Some(ref max_ver) = config.max_tls_version {
        let version = parse_tls_version(max_ver)?;
        ssl_builder
            .set_max_proto_version(Some(version))
            .map_err(|e| ClientError::tls(format!("failed to set max TLS version: {}", e)))?;
    }
    // ALPN: default to http/1.1-only for backward compatibility with
    // existing direct-connection callers (request_target/resolve_ip
    // paths can't meaningfully negotiate h2 anyway). If the caller
    // explicitly set `alpn_protocols`, honor it — that's how raw H2
    // callers (e.g. HTTP/2 smuggling probes) opt in.
    let alpn_wire: Vec<u8> = match &config.alpn_protocols {
        Some(protos) => encode_alpn_protocols(protos)?,
        None => b"\x08http/1.1".to_vec(),
    };
    ssl_builder
        .set_alpn_protos(&alpn_wire)
        .map_err(|e| ClientError::tls(format!("failed to set ALPN: {}", e)))?;

    let ssl_connector = ssl_builder.build();
    let mut ssl_conf = openssl::ssl::Ssl::new(ssl_connector.context())
        .map_err(|e| ClientError::tls(format!("SSL conf failed: {}", e)))?;

    // SNI = original hostname, NOT the resolved IP
    if host.parse::<std::net::IpAddr>().is_err() {
        ssl_conf
            .set_hostname(&host)
            .map_err(|e| ClientError::tls(format!("SNI setup failed: {}", e)))?;
    }
    // Hostname verification: when verify mode is PEER, pin the
    // expected identity so OpenSSL checks the cert's SAN/CN.
    if ssl_conf.verify_mode() != openssl::ssl::SslVerifyMode::NONE {
        let param = ssl_conf.param_mut();
        match host.parse::<std::net::IpAddr>() {
            Ok(ip) => param
                .set_ip(ip)
                .map_err(|e| ClientError::tls(format!("hostname verify setup failed: {}", e)))?,
            Err(_) => param
                .set_host(&host)
                .map_err(|e| ClientError::tls(format!("hostname verify setup failed: {}", e)))?,
        }
    }

    let mut tls_stream = tokio_openssl::SslStream::new(ssl_conf, tcp)
        .map_err(|e| ClientError::tls(format!("TLS stream setup failed: {}", e)))?;

    tokio::time::timeout(connect_timeout, Pin::new(&mut tls_stream).connect())
        .await
        .map_err(|_| {
            ClientError::timeout(format!(
                "TLS handshake with {} timed out after {}s",
                host,
                config.timeout()
            ))
        })?
        .map_err(|e| ClientError::tls(format!("TLS handshake failed: {}", e)))?;

    let cert_info = extract_cert_info(tls_stream.ssl());
    let negotiated_alpn = tls_stream
        .ssl()
        .selected_alpn_protocol()
        .and_then(|b| std::str::from_utf8(b).ok().map(String::from));

    Ok((Box::new(tls_stream), cert_info, negotiated_alpn, peer_ip))
}

/// One-shot request over a direct, un-pooled connection. Used when
/// `resolve_ip` or `request_target` is set and hyper's Client wrapper would
/// either normalize the URI (stripping absolute-form) or route through the
/// shared connection pool, neither of which matches the caller's intent for
/// these specialized requests (host_header, generic_ssrf, virtualhost
/// discovery).
///
/// Speaks whatever ALPN negotiated. `connect_stream` offers http/1.1 alone
/// unless the caller set `alpn_protocols`, so this is HTTP/1.1 by default and
/// HTTP/2 only when asked for and agreed to.
async fn dispatch_direct(
    target_uri: &http::Uri,
    config: &RequestConfig,
    log: &DebugLog,
) -> Result<(SingleResponse, Option<CertInfo>, Option<IpAddr>), ClientError> {
    let v = config.verbosity;
    let (stream, cert_info, alpn, peer_ip) = connect_stream(target_uri, config, log).await?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let h2 = alpn.as_deref() == Some("h2");

    // HTTP/2 carries the target in `:path`, which hyper derives from the
    // request URI, so there is no request-line for `request_target` to
    // control and no way to hand hyper a verbatim one. Say so instead of
    // quietly sending something else: an odd `:path` is a real primitive
    // (H2-to-H1 downgrade smuggling), it just needs the raw path to build.
    if h2 && config.request_target.is_some() {
        return Err(ClientError::other(
            "request_target cannot be sent over HTTP/2: hyper builds :path from the \
             request URI, so a verbatim request target has nowhere to go. Offer \
             http/1.1 in alpn_protocols, or use raw_connect with blasthttp.h2 to \
             write the pseudo-headers yourself."
                .to_string(),
        ));
    }

    let mut sender = if h2 {
        debug_record(log, v, 1, "   ALPN negotiated h2, dispatching over HTTP/2");
        let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| ClientError::connection(format!("HTTP/2 handshake failed: {}", e)))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        DirectSender::Http2(sender)
    } else {
        let (sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| ClientError::connection(format!("HTTP handshake failed: {}", e)))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        DirectSender::Http1(sender)
    };

    let request_uri = if let Some(ref rt) = config.request_target {
        rt.parse::<http::Uri>()
            .map_err(|e: http::uri::InvalidUri| {
                ClientError::invalid_url(format!("invalid request_target '{}': {}", rt, e))
            })?
    } else {
        target_uri.clone()
    };

    // Use origin-form unless request_target was explicitly set (caller wants
    // exact control over the request-line, e.g. absolute-form for SSRF testing).
    // The low-level http1 sender below doesn't auto-populate Host from the URI
    // the way the pooled high-level client does, so we ask build_request to do
    // it manually.
    //
    // HTTP/2 has neither: hyper needs the whole URI to build :scheme,
    // :authority and :path, and a Host header of our own would duplicate
    // :authority in the HPACK block.
    let request = if h2 {
        build_request(&request_uri, config, false, false, None)?
    } else {
        let use_origin_form = config.request_target.is_none();
        build_request(&request_uri, config, use_origin_form, true, None)?
    };

    debug_record(log, v, 1, "   Request headers:");
    for (name, value) in request.headers() {
        debug_record(
            log,
            v,
            1,
            &format!("     {}: {}", name, value.to_str().unwrap_or("<binary>")),
        );
    }
    debug_record(log, v, 1, "   Sending request via dispatch_direct...");

    let hyper_response = sender.send_request(request).await.map_err(|e| {
        let msg = format!("dispatch_direct request failed: {}", e);
        let err_str = e.to_string().to_lowercase();
        if err_str.contains("ssl") || err_str.contains("tls") || err_str.contains("certificate") {
            ClientError::tls(msg)
        } else {
            ClientError::connection(msg)
        }
    })?;

    let resp = parse_response(hyper_response, config, log).await?;
    Ok((resp, cert_info, peer_ip))
}

/// The two one-shot senders `dispatch_direct` can end up holding, picked by
/// what ALPN negotiated. Separate types in hyper, same job here.
enum DirectSender {
    Http1(hyper::client::conn::http1::SendRequest<FullBody>),
    Http2(hyper::client::conn::http2::SendRequest<FullBody>),
}

impl DirectSender {
    async fn send_request(
        &mut self,
        request: hyper::Request<FullBody>,
    ) -> hyper::Result<hyper::Response<hyper::body::Incoming>> {
        match self {
            DirectSender::Http1(s) => s.send_request(request).await,
            DirectSender::Http2(s) => s.send_request(request).await,
        }
    }
}

/// Stream types returned by `connect_stream`: plain TCP or TLS over TCP.
/// Boxed as `Box<dyn IoReadWrite + Send + Unpin>` so callers can hold the
/// stream without knowing which variant they got.
pub(crate) trait IoReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl IoReadWrite for tokio::net::TcpStream {}
impl IoReadWrite for tokio_openssl::SslStream<tokio::net::TcpStream> {}

/// Forward proxy dispatch: connect to proxy via TCP, send request with
/// absolute-form URI (e.g. `GET http://target/path HTTP/1.1`).
///
/// Uses hyper's low-level http1::SendRequest instead of Client, because
/// Client normalizes URIs to origin form (stripping scheme+authority).
async fn dispatch_forward_proxy(
    proxy_url: &str,
    target_uri: &http::Uri,
    config: &RequestConfig,
    log: &DebugLog,
    redirect_cookies: Option<&str>,
) -> Result<SingleResponse, ClientError> {
    let proxy_uri: http::Uri = proxy_url.parse().map_err(|e: http::uri::InvalidUri| {
        ClientError::invalid_url(format!("invalid proxy URL: {}", e))
    })?;
    let proxy_host = proxy_uri
        .host()
        .ok_or_else(|| ClientError::other("proxy URL has no host".to_string()))?;
    let proxy_port = proxy_uri.port_u16().unwrap_or(8080);
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

    debug_record(
        log,
        config.verbosity,
        1,
        &format!("   Forward proxy: connecting to {}", proxy_addr,),
    );

    // TCP connect to the proxy
    let tcp = tokio::net::TcpStream::connect(&proxy_addr)
        .await
        .map_err(|e| {
            ClientError::connection(format!("failed to connect to proxy {}: {}", proxy_addr, e))
        })?;
    let io = hyper_util::rt::TokioIo::new(tcp);

    // HTTP/1.1 handshake — gives us a SendRequest that preserves the URI as-is
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| ClientError::connection(format!("proxy handshake failed: {}", e)))?;

    // Drive the connection in the background
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Build request with absolute-form URI (SendRequest does NOT normalize it).
    // The low-level http1 sender doesn't auto-populate Host, so add it manually.
    let request = build_request(target_uri, config, false, true, redirect_cookies)?;
    let v = config.verbosity;

    debug_record(log, v, 1, "   Request headers:");
    for (name, value) in request.headers() {
        debug_record(
            log,
            v,
            1,
            &format!("     {}: {}", name, value.to_str().unwrap_or("<binary>")),
        );
    }
    debug_record(log, v, 1, "   Sending request via forward proxy...");

    let hyper_response = sender.send_request(request).await.map_err(|e| {
        let msg = format!("forward proxy request failed: {}", e);
        ClientError::connection(msg)
    })?;

    parse_response(hyper_response, config, log).await
}

fn build_request(
    uri: &http::Uri,
    config: &RequestConfig,
    origin_form: bool,
    manual_host_header: bool,
    // Cookies picked up from earlier hops of this redirect chain, already
    // filtered down to the ones that apply to `uri` and to names the caller
    // didn't set themselves. Merged into the caller's own `Cookie` header
    // when there is one, so we never send two.
    redirect_cookies: Option<&str>,
) -> Result<hyper::Request<FullBody>, ClientError> {
    // For direct connections (dispatch_direct), use origin-form (path + query only)
    // in the request-line per RFC 7230 §5.3.1. For pooled/client connections,
    // hyper needs the full URI for routing.
    let effective_uri = if origin_form {
        let path = uri.path();
        if let Some(q) = uri.query() {
            format!("{}?{}", path, q)
                .parse::<http::Uri>()
                .unwrap_or_else(|_| uri.clone())
        } else if path.is_empty() {
            "/".parse::<http::Uri>().unwrap()
        } else {
            path.parse::<http::Uri>().unwrap_or_else(|_| uri.clone())
        }
    } else {
        uri.clone()
    };
    let mut builder = hyper::Request::builder()
        .method(config.method())
        .uri(effective_uri);

    // Check which default headers the caller has already provided.
    // Note: we only check for the *presence* of a custom header to decide whether
    // to add a default. Custom headers are always appended as-is (including
    // duplicates), so callers can send multiple Host headers if needed.
    let custom = config.headers.as_deref().unwrap_or(&[]);
    let has_custom_host = custom.iter().any(|(k, _)| k.eq_ignore_ascii_case("host"));
    let has_custom_ua = custom
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
    let has_custom_ae = custom
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"));

    // Auto-set Host from URI (HTTP/1.1 requirement) unless the caller supplies
    // their own.  hyper's low-level handshake API (used by dispatch_direct for
    // resolve_ip / request_target, and by the forward-proxy path) does not
    // auto-set Host, so we must do it. For the pooled high-level client we
    // skip this — hyper populates Host (HTTP/1.1) or :authority (HTTP/2) from
    // the URI itself, and adding our own Host on top would land as a duplicate
    // header in the HTTP/2 HPACK block alongside :authority, which some
    // origin servers/WAFs reject as a protocol violation.
    if manual_host_header
        && !has_custom_host
        && let Some(authority) = uri.authority()
    {
        builder = builder.header("Host", authority.as_str());
    }

    if !has_custom_ua {
        builder = builder.header("User-Agent", "blasthttp/0.1.0");
    }
    if !has_custom_ae {
        builder = builder.header("Accept-Encoding", "gzip, deflate, br");
    }

    // Emit the caller's headers, folding any redirect-chain cookies into the
    // first `Cookie` header they supplied. If they supplied none, the
    // chain's cookies go out as their own header after the caller's.
    //
    // The chain's list can't contain a name the caller set, because
    // `ChainCookies` refuses to store one, so this concatenation never
    // produces the same
    // name twice. That matters: duplicate names are read inconsistently
    // across servers (some take the first, some the last), so a request
    // carrying both would behave differently depending on the target.
    let mut merged_cookies = false;
    if let Some(ref custom_headers) = config.headers {
        for (name, value) in custom_headers {
            if let Some(extra) = redirect_cookies
                && !merged_cookies
                && name.eq_ignore_ascii_case("cookie")
            {
                merged_cookies = true;
                // Join on exactly one `; `. A caller's header often ends with
                // a stray separator, and pasting onto it leaves an empty pair
                // in the middle of the list, which strict parsers treat as
                // the end of the header: the chain's cookies would be dropped
                // by the target while the log here said they were sent.
                let caller = value.trim().trim_end_matches([';', ' ']);
                let merged = if caller.is_empty() {
                    extra.to_string()
                } else {
                    format!("{}; {}", caller, extra)
                };
                builder = builder.header(name.as_str(), merged);
                continue;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }
    }
    if let Some(extra) = redirect_cookies
        && !merged_cookies
    {
        builder = builder.header("Cookie", extra);
    }

    let body_bytes = config.body.clone().unwrap_or_default();
    builder
        .body(http_body_util::Full::new(bytes::Bytes::from(body_bytes)))
        .map_err(|e| ClientError::other(format!("failed to build request: {}", e)))
}

async fn parse_response(
    hyper_response: hyper::Response<hyper::body::Incoming>,
    config: &RequestConfig,
    log: &DebugLog,
) -> Result<SingleResponse, ClientError> {
    let v = config.verbosity;
    let status = hyper_response.status().as_u16();

    let location = hyper_response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let mut headers: Vec<(String, String)> = Vec::new();
    debug_record(log, v, 1, "   Response headers:");
    for (name, value) in hyper_response.headers() {
        let val_str = value.to_str().unwrap_or("<binary>").to_string();
        debug_record(log, v, 1, &format!("     {}: {}", name, val_str));
        headers.push((name.to_string(), val_str));
    }

    // A repeated `Content-Encoding` line means the same thing as one line
    // carrying the values comma-joined, in the order they arrived (RFC 9110
    // 5.3), and stacked codings show up both ways: an edge that compresses
    // an already-compressed body usually adds its own line rather than
    // editing the one below it. Reading only the first line would peel one
    // layer and hand back a still-compressed body. The lines themselves are
    // already in `headers` untouched, so a caller looking for the
    // front-end/back-end disagreement can still see it.
    let content_encoding = hyper_response
        .headers()
        .get_all("content-encoding")
        .iter()
        // A value that isn't text is a coding we can't name, let alone
        // undo. `decompress` hands the body back as it arrived for a token
        // it doesn't recognize, which is what we want here.
        .map(|v| v.to_str().unwrap_or("<unreadable>"))
        .collect::<Vec<_>>()
        .join(",")
        .to_lowercase();

    let max_body = config.max_body();
    let (raw_bytes, cut_by_cap) = read_body(hyper_response.into_body(), max_body).await?;
    debug_record(
        log,
        v,
        1,
        &format!("   Raw body: {} bytes", raw_bytes.len()),
    );
    if cut_by_cap {
        debug_record(
            log,
            v,
            1,
            &format!("   Body cut at the {} byte max_body cap", max_body),
        );
    }

    // Which shape of `deflate` a server sends says something about what is
    // in front of it, so record it while the wire bytes are still in hand.
    // Only the outermost coding describes those bytes, and that's the last
    // entry in the list. See `decode_deflate`.
    if content_encoding
        .rsplit(',')
        .next()
        .is_some_and(|token| token.trim() == "deflate")
    {
        debug_record(
            log,
            v,
            1,
            &format!(
                "   deflate body: {}",
                if has_zlib_header(&raw_bytes) {
                    "zlib header present (RFC 1950)"
                } else {
                    "no zlib header, raw stream (RFC 1951)"
                }
            ),
        );
    }

    let (body_bytes, decode_error) = if content_encoding.is_empty() {
        (raw_bytes, None)
    } else {
        let decoded = decompress(&content_encoding, &raw_bytes, max_body);
        match decoded.decode_error {
            None => {
                debug_record(
                    log,
                    v,
                    1,
                    &format!(
                        "   Decompressed ({}): {} -> {} bytes",
                        content_encoding,
                        raw_bytes.len(),
                        decoded.body.len()
                    ),
                );
                (decoded.body, None)
            }
            // Nothing inflated at all. The status line and headers still
            // arrived cleanly, and these are the bytes the server really
            // sent, so hand them back undecoded rather than throw the whole
            // response away. Discarding it would look identical to an
            // unreachable host, which loses far more than a body we can't
            // read.
            //
            // The reason travels with the response as `decode_error`, since
            // a caller hashing or matching bodies has no other way to tell
            // compressed bytes from content, and the debug log only reaches
            // them at verbosity >= 1.
            Some(reason) => {
                let cause = if cut_by_cap {
                    format!("{} (body hit the max_body cap mid-stream)", reason)
                } else {
                    reason
                };
                debug_record(
                    log,
                    v,
                    1,
                    &format!(
                        "   Body not fully decoded, {} bytes: {}",
                        decoded.body.len(),
                        cause
                    ),
                );
                (decoded.body, Some(cause))
            }
        }
    };

    if body_bytes.len() >= max_body {
        debug_record(
            log,
            v,
            1,
            &format!("   Body truncated at {} bytes", max_body),
        );
    }

    Ok(SingleResponse {
        status,
        headers,
        body_bytes,
        location,
        decode_error,
    })
}

struct SingleResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body_bytes: Vec<u8>,
    location: Option<String>,
    /// Why `body_bytes` is not decoded content, when it isn't. See
    /// `Response::decode_error`.
    decode_error: Option<String>,
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn resolve_redirect(current: &http::Uri, location: &str) -> Result<http::Uri, ClientError> {
    let sanitized = sanitize_uri(location);
    if let Ok(uri) = sanitized.parse::<http::Uri>()
        && uri.scheme().is_some()
    {
        return Ok(uri);
    }

    let scheme = current.scheme_str().unwrap_or("https");
    let authority = current.authority().ok_or_else(|| {
        ClientError::invalid_url(format!(
            "no authority in current URL to resolve relative redirect: {}",
            location
        ))
    })?;

    let absolute = format!("{}://{}{}", scheme, authority, sanitized);
    absolute.parse().map_err(|e: http::uri::InvalidUri| {
        ClientError::invalid_url(format!("invalid redirect URL '{}': {}", absolute, e))
    })
}

// ── HttpClient implementation ─────────────────────────────────────

/// Compute exponential backoff: min(2^attempt × min_wait, max_wait)
fn retry_backoff(attempt: u32, min_wait: Duration, max_wait: Duration) -> Duration {
    let factor = 2u64.saturating_pow(attempt);
    let backoff = min_wait.saturating_mul(factor as u32);
    std::cmp::min(backoff, max_wait)
}

impl HttpClient for HyperClient {
    async fn send(&self, config: &RequestConfig) -> Result<Response, ClientError> {
        config.validate_proxy().map_err(ClientError::other)?;
        let timeout_duration = Duration::from_secs(config.timeout());
        let max_retries = config.max_retries();
        let min_wait = config.retry_wait_min();
        let max_wait = config.retry_wait_max();
        let log = new_debug_log();

        let mut last_err = None;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                let backoff = retry_backoff(attempt - 1, min_wait, max_wait);
                debug_record(
                    &log,
                    config.verbosity,
                    1,
                    &format!(
                        "   Retry {}/{} after {}ms",
                        attempt,
                        max_retries,
                        backoff.as_millis(),
                    ),
                );
                tokio::time::sleep(backoff).await;
            }

            match tokio::time::timeout(timeout_duration, self.send_inner(config, &log)).await {
                Ok(Ok(response)) => {
                    let status = response.status;
                    if super::ErrorKind::Status(status).is_retryable() && attempt < max_retries {
                        debug_record(
                            &log,
                            config.verbosity,
                            1,
                            &format!("   Retryable status {} from {}", status, config.url,),
                        );
                        last_err = Some(ClientError::status(
                            status,
                            format!("server returned {} for {}", status, config.url),
                        ));
                        continue;
                    }
                    return Ok(response);
                }
                Ok(Err(e)) => {
                    if e.kind.is_retryable() && attempt < max_retries {
                        debug_record(
                            &log,
                            config.verbosity,
                            1,
                            &format!("   Retryable error: {}", e.message,),
                        );
                        last_err = Some(e);
                        continue;
                    }
                    return Err(e);
                }
                Err(_) => {
                    return Err(ClientError::timeout(format!(
                        "request timed out after {}s",
                        config.timeout()
                    )));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| ClientError::other("all retries exhausted".to_string())))
    }
}

impl HyperClient {
    async fn send_inner(
        &self,
        config: &RequestConfig,
        log: &DebugLog,
    ) -> Result<Response, ClientError> {
        let v = config.verbosity;
        let start = Instant::now();

        let sanitized_url = sanitize_uri(&config.url);
        let mut uri: http::Uri = sanitized_url.parse().map_err(|e: http::uri::InvalidUri| {
            ClientError::invalid_url(format!("invalid URL: {}", e))
        })?;

        debug_record(log, v, 1, &format!("-> {} {}", config.method(), uri));
        if let Some(proxy) = config.effective_proxy(uri.host().unwrap_or("")) {
            debug_record(log, v, 1, &format!("   Proxy: {}", proxy));
        }
        if !config.should_verify_certs() {
            debug_record(log, v, 1, "   TLS certificate validation: disabled");
        }
        if let Some(ref ciphers) = config.cipher_string {
            debug_record(log, v, 1, &format!("   Cipher string: {}", ciphers));
        }
        if let Some(ref min_ver) = config.min_tls_version {
            debug_record(log, v, 1, &format!("   Min TLS: {}", min_ver));
        }
        if let Some(ref max_ver) = config.max_tls_version {
            debug_record(log, v, 1, &format!("   Max TLS: {}", max_ver));
        }
        if let Some(ref resolve_ip) = config.resolve_ip {
            debug_record(log, v, 1, &format!("   Resolve IP: {}", resolve_ip));
        }
        if let Some(ref rt) = config.request_target {
            debug_record(log, v, 1, &format!("   Request target: {}", rt));
        }

        // dispatch_direct: used when resolve_ip or request_target is set.
        // Bypasses the cached connection pool — opens a fresh TCP connection.
        if config.resolve_ip.is_some() || config.request_target.is_some() {
            let redirect_chain: Vec<RedirectHop> = Vec::new();
            let (resp, cert_info, peer_ip) = dispatch_direct(&uri, config, log).await?;
            let hop_ms = start.elapsed().as_millis();
            debug_record(log, v, 1, &format!("<- {} ({}ms)", resp.status, hop_ms));

            // No redirect following for dispatch_direct — these are specialized
            // requests (host_header, SSRF) that need exact control.
            let elapsed_ms = start.elapsed().as_millis() as u64;
            let debug_log = log.lock().map(|guard| guard.clone()).unwrap_or_default();

            return Ok(Response {
                url: uri.to_string(),
                status: resp.status,
                headers: resp.headers,
                body_bytes: resp.body_bytes,
                elapsed_ms,
                redirect_chain,
                cert_info,
                peer_ip: peer_ip.map(|ip| ip.to_string()),
                request_url: config.url.clone(),
                request_method: config.method().to_string(),
                debug_log,
                decode_error: resp.decode_error,
                body_cache: std::sync::OnceLock::new(),
                raw_headers_cache: std::sync::OnceLock::new(),
                cookies_cache: std::sync::OnceLock::new(),
                hash_cache: std::sync::OnceLock::new(),
            });
        }

        let mut redirect_chain: Vec<RedirectHop> = Vec::new();
        let mut hops = 0u32;

        // Cookies picked up as we walk this chain. Created here and dropped
        // when the request returns, so two concurrent requests can never see
        // each other's cookies and a request's result depends only on its own
        // inputs. `hop_cookies` is the `Cookie` header for the hop we're about
        // to make, recomputed per hop because each one may be a different host.
        // The caller's own cookies are recorded up front so the chain can
        // never touch them: whatever they put in a `Cookie` header is what
        // every hop sends.
        let mut chain_cookies = config.should_forward_redirect_cookies().then(|| {
            crate::cookies::ChainCookies::with_caller_cookies(crate::cookies::caller_cookie_names(
                config.headers.as_deref().unwrap_or(&[]),
            ))
        });
        let mut hop_cookies: Option<String> = None;

        loop {
            // Decide the connection mode for the *current* target host on every
            // hop, not just the first. A redirect can send the request to a
            // different host, and the proxy / no_proxy decision has to follow
            // it. Freezing the first hop's choice would otherwise let a request
            // that started direct keep connecting directly after a redirect onto
            // a proxied host (leaking traffic past the proxy), and let a request
            // that started proxied keep using the proxy after a redirect onto a
            // no_proxy host. Clients are cached by mode, so hops that share a
            // mode reuse the same client.
            let mode = Self::conn_mode(config, &uri)?;

            // Forward proxy: dispatch directly via TCP + http1::SendRequest
            // (bypasses hyper Client's URI normalization to preserve absolute-form)
            let is_forward_proxy = matches!(&mode, ConnMode::ForwardProxy(_));
            let proxy_url_for_fwd = if let ConnMode::ForwardProxy(ref url) = mode {
                Some(url.clone())
            } else {
                None
            };

            // For non-forward-proxy modes, get the cached hyper Client.
            let cached = if is_forward_proxy {
                None
            } else {
                Some(self.get_or_build(config, &mode)?)
            };

            let resp = if let Some(ref proxy_url) = proxy_url_for_fwd {
                dispatch_forward_proxy(proxy_url, &uri, config, log, hop_cookies.as_deref()).await?
            } else {
                dispatch_request(
                    &cached.as_ref().unwrap().inner,
                    &uri,
                    config,
                    log,
                    hop_cookies.as_deref(),
                )
                .await?
            };
            let hop_ms = start.elapsed().as_millis();
            debug_record(log, v, 1, &format!("<- {} ({}ms)", resp.status, hop_ms));

            // Per-hop peer IP lookup. Returns None when:
            //   • the request went through a proxy (the connector recorded
            //     the proxy IP under the proxy's authority, so the target's
            //     authority isn't in the map)
            //   • forward-proxy dispatch (bypasses the connector entirely)
            //   • peer_addr() failed at connect time (vanishingly rare)
            let hop_peer_ip = peer_slot_key(&uri).and_then(|key| {
                let cached = cached.as_ref()?;
                let map = cached.peer_slot.lock().ok()?;
                map.get(&key).map(|ip| ip.to_string())
            });

            if is_redirect(resp.status) && config.should_follow_redirects() {
                hops += 1;
                if hops > config.redirect_limit() {
                    return Err(ClientError::too_many_redirects(format!(
                        "too many redirects (limit: {})",
                        config.redirect_limit()
                    )));
                }

                let location = resp.location.as_deref().ok_or_else(|| {
                    ClientError::other(format!("redirect {} but no Location header", resp.status))
                })?;

                let next_uri = resolve_redirect(&uri, location)?;
                debug_record(
                    log,
                    v,
                    1,
                    &format!("   Redirect #{}: {} -> {}", hops, uri, next_uri),
                );

                redirect_chain.push(RedirectHop {
                    url: uri.to_string(),
                    status: resp.status,
                    peer_ip: hop_peer_ip,
                });

                // Take this hop's `Set-Cookie` headers, then work out which of
                // everything collected so far applies to where we're going.
                // The domain / path / Secure rules are what stop a cookie from
                // following a redirect onto a host it doesn't belong to.
                if let Some(chain) = chain_cookies.as_mut() {
                    let rejected = chain.store(&resp.headers, &uri);
                    if !rejected.caller_owned.is_empty() {
                        debug_record(
                            log,
                            v,
                            1,
                            &format!(
                                "   Kept the caller's own cookie(s) over a Set-Cookie for: {}",
                                rejected.caller_owned.join(", ")
                            ),
                        );
                    }
                    // Say so rather than quietly holding fewer cookies than
                    // the chain set: a cap nobody can see reads as coverage.
                    if !rejected.over_limit.is_empty() {
                        debug_record(
                            log,
                            v,
                            1,
                            &format!(
                                "   Cookie limit reached, dropped: {}",
                                rejected.over_limit.join(", ")
                            ),
                        );
                    }
                    hop_cookies = chain.header_for(&next_uri);
                    if let Some(ref c) = hop_cookies {
                        debug_record(log, v, 1, &format!("   Sending cookies: {}", c));
                    }
                }

                uri = next_uri;
                continue;
            }

            let cert_info = cached
                .as_ref()
                .and_then(|c| c.cert_slot.lock().ok())
                .and_then(|guard| guard.clone());

            let peer_ip = hop_peer_ip;

            let elapsed_ms = start.elapsed().as_millis() as u64;
            debug_record(
                log,
                v,
                1,
                &format!(
                    "   Total time: {}ms ({} redirect(s))",
                    elapsed_ms,
                    redirect_chain.len()
                ),
            );

            if let Some(ref info) = cert_info {
                debug_record(log, v, 1, &format!("   Cert CN: {:?}", info.common_name));
                debug_record(log, v, 1, &format!("   Cert SANs: {:?}", info.sans));
            }

            // Extract collected debug messages
            let debug_log = log.lock().map(|guard| guard.clone()).unwrap_or_default();

            return Ok(Response {
                url: uri.to_string(),
                status: resp.status,
                headers: resp.headers,
                body_bytes: resp.body_bytes,
                elapsed_ms,
                redirect_chain,
                cert_info,
                peer_ip,
                request_url: config.url.clone(),
                request_method: config.method().to_string(),
                debug_log,
                decode_error: resp.decode_error,
                body_cache: std::sync::OnceLock::new(),
                raw_headers_cache: std::sync::OnceLock::new(),
                cookies_cache: std::sync::OnceLock::new(),
                hash_cache: std::sync::OnceLock::new(),
            });
        }
    }
}

// ── Decompression ─────────────────────────────────────────────────

/// Inflate a response body, bounded to `max_size` bytes of output.
///
/// A response whose status line and headers arrived cleanly should not be
/// thrown away just because the body didn't inflate, so this is deliberately
/// forgiving in two places:
///
///   * An empty body is empty, whatever the header claims. Servers routinely
///     put a `Content-Encoding` on a response that has no body at all: any
///     bodyless redirect, a `HEAD` (which echoes the entity headers of the
///     `GET` it mirrors), a `304` (which carries the headers a `200` would).
///     Handing zero bytes to a decoder makes it report a missing stream,
///     which is true but not interesting.
///   * A stream that breaks partway keeps whatever inflated before the break.
///     The usual cause is our own `max_size` cap in `read_body` cutting the
///     compressed bytes mid-stream, so the remainder was never going to
///     arrive. Partial content beats no response.
///
/// A body that yields nothing at all comes back as it arrived, marked
/// undecoded, so a genuinely mislabelled or corrupt body is still reported
/// rather than passed off as empty or as content. See `Decoded`.
///
/// `max_size` bounds the output of each layer here. `read_body` bounds the
/// input separately, since both directions need it: compression ratios are
/// unbounded in principle, so a small response can inflate into an
/// arbitrarily large allocation, and a response can be arbitrarily large on
/// the wire to begin with.
///
/// `encoding` is the whole header value, which is an ordered list of the
/// codings applied to the body, so undoing it means walking them in reverse.
/// The caller lowercases it.
fn decompress(encoding: &str, data: &[u8], max_size: usize) -> Decoded {
    if data.is_empty() {
        return Decoded::content(Vec::new());
    }

    let mut codecs = Vec::new();
    for token in encoding.split(',') {
        let token = token.trim();
        // Empty list elements are legal noise a recipient is meant to
        // ignore (RFC 9110 5.6.1.2), and joining repeated header lines can
        // produce them from a line that carried no value at all.
        if token.is_empty() {
            continue;
        }
        match Codec::from_token(token) {
            // `identity` means no coding was applied, so there is nothing
            // to undo for that entry.
            Some(Codec::Identity) => {}
            Some(codec) => codecs.push(codec),
            // A coding we can't undo hides whatever is beneath it, so
            // decoding the inner layers would produce nonsense. Hand back
            // the bytes as they arrived instead of guessing.
            None => {
                return Decoded::raw(data, format!("unsupported content-encoding '{}'", token));
            }
        }
    }

    let declared = codecs.len();
    let mut remaining = codecs.into_iter().rev();
    let Some(outermost) = remaining.next() else {
        // Nothing but `identity`.
        return Decoded::content(data.to_vec());
    };

    // Set when a layer produced output without decoding cleanly. The bytes
    // are worth keeping and are not content, so this travels out with them.
    let mut incomplete: Option<String> = None;

    let mut out = match decode_one(outermost, data, max_size) {
        Inflated::Whole(out) => out,
        Inflated::Partial(out, why) => {
            incomplete = Some(why);
            out
        }
        // Nothing came off at all, so the bytes are what arrived.
        Inflated::Failed(reason) => return Decoded::raw(data, reason),
    };
    let mut peeled = 1;

    for codec in remaining {
        match decode_one(codec, &out, max_size) {
            Inflated::Whole(next) => {
                out = next;
                peeled += 1;
            }
            Inflated::Partial(next, why) => {
                out = next;
                peeled += 1;
                // Keep the outermost complaint: it's the one that describes
                // the bytes as they arrived.
                incomplete.get_or_insert(why);
            }
            // A layer underneath one that did come off won't inflate. Keep
            // the deepest peel rather than reverting to the original bytes,
            // because the likeliest cause is a header that overstates the
            // codings rather than a body that was really encoded that many
            // times: a proxy re-adding `Content-Encoding: gzip` in front of
            // a backend that already set it, without compressing again,
            // gives `gzip, gzip` over a singly-compressed body. What is in
            // hand there is the body. Still flagged, since the other
            // possibility is a layer genuinely left on.
            Inflated::Failed(reason) => {
                return Decoded::partial(
                    out,
                    format!(
                        "{} of {} content-encoding layers came off: {}",
                        peeled, declared, reason
                    ),
                );
            }
        }
    }

    match incomplete {
        Some(reason) => Decoded::partial(out, reason),
        None => Decoded::content(out),
    }
}

/// The outcome of `decompress`: bytes for the caller, plus whether they are
/// actually decoded content.
///
/// There is no error variant on purpose. A body that won't decode is not
/// grounds for dropping a response whose status line and headers arrived
/// cleanly, so every path here produces bytes. What the caller must not do is
/// mistake one kind for the other, which is what `decode_error` is for.
struct Decoded {
    body: Vec<u8>,
    /// `None` when `body` is content: every declared coding came off, and
    /// each decoder read its stream through to a clean end.
    ///
    /// `Some(reason)` when it isn't, which covers three shapes. Nothing came
    /// off, and `body` is exactly what arrived. Some layers came off and
    /// `body` is as far in as we got. Or a layer produced output and then
    /// reported that the stream was cut or damaged, so `body` is a prefix, or
    /// bytes that don't match what was compressed. The reason says which.
    ///
    /// That last one is the case worth being careful about, since the bytes
    /// look like an ordinary body and aren't one.
    ///
    /// A body cut by `max_body` lands here too when the cap ends the wire
    /// read before the decoder is done, which happens on bodies that barely
    /// compress. The same cap bounds both the bytes read and the bytes kept,
    /// so which limit trips first depends on the body's entropy: a highly
    /// compressible body fills the output cap and reads clean, a
    /// near-incompressible one runs out of input and is flagged. Flagged is
    /// the deliberate choice, since a truncated prefix is what a middlebox
    /// cutting a response also produces.
    decode_error: Option<String>,
}

impl Decoded {
    fn content(body: Vec<u8>) -> Self {
        Decoded {
            body,
            decode_error: None,
        }
    }

    fn raw(data: &[u8], reason: String) -> Self {
        Decoded {
            body: data.to_vec(),
            decode_error: Some(reason),
        }
    }

    fn partial(body: Vec<u8>, reason: String) -> Self {
        Decoded {
            body,
            decode_error: Some(reason),
        }
    }
}

/// One entry from a `Content-Encoding` list.
#[derive(Clone, Copy)]
enum Codec {
    Gzip,
    Deflate,
    Brotli,
    Identity,
}

impl Codec {
    fn from_token(token: &str) -> Option<Self> {
        match token {
            // `x-gzip` is a deprecated alias for `gzip` that servers do
            // still send.
            "gzip" | "x-gzip" => Some(Codec::Gzip),
            "deflate" => Some(Codec::Deflate),
            "br" => Some(Codec::Brotli),
            "identity" => Some(Codec::Identity),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Codec::Gzip => "gzip",
            Codec::Deflate => "deflate",
            Codec::Brotli => "brotli",
            Codec::Identity => "identity",
        }
    }
}

/// Undo a single coding. Nothing here is fatal to a response, so the failure
/// case is a reason string rather than a `ClientError`: see `Decoded`.
fn decode_one(codec: Codec, data: &[u8], max_size: usize) -> Inflated {
    match codec {
        Codec::Gzip => read_bounded(flate2::read::GzDecoder::new(data), max_size, codec),
        Codec::Deflate => decode_deflate(data, max_size),
        Codec::Brotli => read_bounded(brotli::Decompressor::new(data, 4096), max_size, codec),
        Codec::Identity => Inflated::Whole(data.to_vec()),
    }
}

/// Undo `Content-Encoding: deflate`, which arrives in two different shapes.
///
/// RFC 9110 8.4.1.2 defines it as a zlib stream (RFC 1950) wrapping deflate
/// data, and that is what IIS and several CDN fronts send. Plenty of other
/// servers send a bare deflate stream (RFC 1951) with no zlib wrapper.
/// Neither decoder can read the other's input, and we ask for `deflate` on
/// every request, so both shapes have to work or a real body comes back
/// looking like garbage.
///
/// The first two bytes say which one it is: the low nibble of the first byte
/// is the compression method (8 for deflate) and the pair read big-endian is
/// a multiple of 31. A raw stream can satisfy that by coincidence, so the
/// flavor the header points at is tried first and the other one is the
/// fallback.
fn decode_deflate(data: &[u8], max_size: usize) -> Inflated {
    let attempt = |zlib: bool| -> Inflated {
        if zlib {
            read_bounded(
                flate2::read::ZlibDecoder::new(data),
                max_size,
                Codec::Deflate,
            )
        } else {
            read_bounded(
                flate2::read::DeflateDecoder::new(data),
                max_size,
                Codec::Deflate,
            )
        }
    };

    let zlib_first = has_zlib_header(data);
    match attempt(zlib_first) {
        // Any output settles it. The two flavors don't cross-decode: handed
        // the other one's stream, a decoder rejects the header outright and
        // produces nothing, so output means this was the right flavor even
        // when the stream then turns out to be cut or damaged.
        Inflated::Failed(expected) => match attempt(!zlib_first) {
            // Nothing either way, so report what the header pointed at.
            Inflated::Failed(_) => Inflated::Failed(expected),
            fallback => fallback,
        },
        settled => settled,
    }
}

/// Whether `data` starts with something that reads as a zlib header (RFC 1950
/// 2.2): compression method 8 in the low nibble of CMF, and a CMF/FLG pair
/// that is a multiple of 31. True for every zlib stream, and true for a raw
/// deflate stream only by coincidence, which is why `decode_deflate` keeps a
/// fallback rather than trusting this outright.
fn has_zlib_header(data: &[u8]) -> bool {
    match data {
        [cmf, flg, ..] => cmf & 0x0f == 8 && u16::from_be_bytes([*cmf, *flg]) % 31 == 0,
        _ => false,
    }
}

/// What one decoding attempt produced.
enum Inflated {
    /// The stream ended where it said it would, and checked out.
    Whole(Vec<u8>),
    /// Output, but the decoder and the stream disagreed on the way: bytes cut
    /// off partway, a corrupt block, a checksum that doesn't match. Carries
    /// what the decoder said.
    Partial(Vec<u8>, String),
    /// Nothing inflated at all.
    Failed(String),
}

/// Run a decoder, keeping at most `max_size` bytes of output.
///
/// Hitting `max_size` is not an error: `take` simply ends the stream, so the
/// output cap reads as a clean finish. An error here means the input ran out
/// early or didn't decode, which is worth telling apart from a body that
/// decoded whole even when bytes did come out of it.
fn read_bounded<R: Read>(reader: R, max_size: usize, codec: Codec) -> Inflated {
    let mut buf = Vec::new();
    match reader.take(max_size as u64).read_to_end(&mut buf) {
        Ok(_) => Inflated::Whole(buf),
        Err(e) if buf.is_empty() => {
            Inflated::Failed(format!("{} decompression failed: {}", codec.name(), e))
        }
        // `read_to_end` keeps what it managed to read before the error, and
        // that prefix is usually worth having. It is not content, though: the
        // usual causes are our own cap cutting the compressed bytes mid-stream
        // and a body that was damaged or tampered with, and only the second
        // one silently changes what the caller is looking at.
        Err(e) => Inflated::Partial(
            buf,
            format!("{} stream did not decode cleanly: {}", codec.name(), e),
        ),
    }
}

/// Read a response body, stopping once `max_size` bytes are in hand. Returns
/// the bytes and whether the cap cut the body short.
///
/// The cap bounds what gets read off the wire, not just what gets kept.
/// Buffering a whole body before truncating it leaves `max_body_size` looking
/// like a limit while a target can still answer with a body of any size,
/// including one that never ends, so a caller sweeping untrusted hosts has no
/// bound on memory at all. Stopping early means walking away mid-response,
/// which costs the connection (it can't be reused) and is visible to the
/// server. That is the better trade when the alternative is unbounded, and a
/// caller who needs the connection intact has `raw_connect`.
async fn read_body<B>(body: B, max_size: usize) -> Result<(Vec<u8>, bool), ClientError>
where
    B: hyper::body::Body<Data = bytes::Bytes>,
    B::Error: std::fmt::Display,
{
    let mut body = std::pin::pin!(body);
    let mut out: Vec<u8> = Vec::new();

    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|e| ClientError::connection(format!("failed to read body: {}", e)))?;
        // Trailers carry no body bytes.
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        if chunk.is_empty() {
            continue;
        }
        let room = max_size - out.len();
        if chunk.len() > room {
            out.extend_from_slice(&chunk[..room]);
            return Ok((out, true));
        }
        out.extend_from_slice(chunk);
    }

    // Falling out of the loop means the body ended on its own, even if it
    // ended exactly on the cap.
    Ok((out, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_attempt_0() {
        let min = Duration::from_secs(1);
        let max = Duration::from_secs(30);
        // 2^0 × 1s = 1s
        assert_eq!(retry_backoff(0, min, max), Duration::from_secs(1));
    }

    #[test]
    fn test_backoff_attempt_1() {
        let min = Duration::from_secs(1);
        let max = Duration::from_secs(30);
        // 2^1 × 1s = 2s
        assert_eq!(retry_backoff(1, min, max), Duration::from_secs(2));
    }

    #[test]
    fn test_backoff_attempt_2() {
        let min = Duration::from_secs(1);
        let max = Duration::from_secs(30);
        // 2^2 × 1s = 4s
        assert_eq!(retry_backoff(2, min, max), Duration::from_secs(4));
    }

    #[test]
    fn test_backoff_caps_at_max() {
        let min = Duration::from_secs(1);
        let max = Duration::from_secs(30);
        // 2^10 × 1s = 1024s, capped at 30s
        assert_eq!(retry_backoff(10, min, max), Duration::from_secs(30));
    }

    #[test]
    fn test_backoff_custom_min() {
        let min = Duration::from_millis(500);
        let max = Duration::from_secs(30);
        // 2^0 × 500ms = 500ms
        assert_eq!(retry_backoff(0, min, max), Duration::from_millis(500));
        // 2^1 × 500ms = 1000ms
        assert_eq!(retry_backoff(1, min, max), Duration::from_millis(1000));
    }

    #[test]
    fn test_build_request_auto_host_from_uri() {
        let uri: http::Uri = "http://example.com:8080/path".parse().unwrap();
        let config = RequestConfig::new("http://example.com:8080/path".to_string());
        let req = build_request(&uri, &config, true, true, None).unwrap();
        assert_eq!(req.headers().get("host").unwrap(), "example.com:8080");
    }

    #[test]
    fn test_build_request_no_manual_host_for_pooled_path() {
        // The pooled high-level client populates Host / :authority from the
        // URI itself, so build_request must not add a Host header on top.
        // Sending both would land as a duplicate :authority + host in the
        // HTTP/2 HPACK block, which some origin servers reject.
        let uri: http::Uri = "http://example.com:8080/path".parse().unwrap();
        let config = RequestConfig::new("http://example.com:8080/path".to_string());
        let req = build_request(&uri, &config, false, false, None).unwrap();
        assert!(req.headers().get("host").is_none());
    }

    #[test]
    fn test_build_request_custom_host_overrides_auto() {
        let uri: http::Uri = "http://example.com:8080/path".parse().unwrap();
        let mut config = RequestConfig::new("http://example.com:8080/path".to_string());
        config.headers = Some(vec![("Host".to_string(), "custom.host".to_string())]);
        let req = build_request(&uri, &config, true, true, None).unwrap();
        // Should only have the custom Host, not auto-derived
        let hosts: Vec<_> = req.headers().get_all("host").iter().collect();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "custom.host");
    }

    #[test]
    fn test_build_request_custom_host_passes_through_pooled_path() {
        // Even on the pooled path (manual_host_header=false), a caller-supplied
        // Host must be preserved — that's how virtualhost / host-header probes
        // override the auto-derived value.
        let uri: http::Uri = "http://example.com:8080/path".parse().unwrap();
        let mut config = RequestConfig::new("http://example.com:8080/path".to_string());
        config.headers = Some(vec![("Host".to_string(), "custom.host".to_string())]);
        let req = build_request(&uri, &config, false, false, None).unwrap();
        let hosts: Vec<_> = req.headers().get_all("host").iter().collect();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "custom.host");
    }

    #[test]
    fn test_build_request_multiple_host_headers() {
        let uri: http::Uri = "http://example.com/".parse().unwrap();
        let mut config = RequestConfig::new("http://example.com/".to_string());
        config.headers = Some(vec![
            ("Host".to_string(), "first.host".to_string()),
            ("Host".to_string(), "second.host".to_string()),
        ]);
        let req = build_request(&uri, &config, true, true, None).unwrap();
        let hosts: Vec<_> = req.headers().get_all("host").iter().collect();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], "first.host");
        assert_eq!(hosts[1], "second.host");
    }

    #[test]
    fn test_chain_cookies_merge_into_a_well_formed_header() {
        // A trailing `;` is the normal shape of a `Cookie` header copied out
        // of a browser or a proxy, and joining onto it blindly produced
        // `a=1;; chain=9`. Strict parsers give up at the empty pair, so the
        // chain's cookies were dropped by the target while the debug log
        // said they went out.
        let uri: http::Uri = "http://example.com/".parse().unwrap();
        for caller in ["a=1", "a=1;", "a=1; ", "a=1 ;  "] {
            let mut config = RequestConfig::new("http://example.com/".to_string());
            config.headers = Some(vec![("Cookie".to_string(), caller.to_string())]);
            let req = build_request(&uri, &config, false, false, Some("chain=9")).unwrap();
            assert_eq!(
                req.headers().get("cookie").unwrap(),
                "a=1; chain=9",
                "caller header {:?}",
                caller
            );
        }

        // An empty `Cookie` header is the same as not having one.
        let mut config = RequestConfig::new("http://example.com/".to_string());
        config.headers = Some(vec![("Cookie".to_string(), String::new())]);
        let req = build_request(&uri, &config, false, false, Some("chain=9")).unwrap();
        assert_eq!(req.headers().get("cookie").unwrap(), "chain=9");
    }

    #[test]
    fn test_build_request_origin_form_strips_authority() {
        let uri: http::Uri = "http://example.com:8080/path?q=1".parse().unwrap();
        let config = RequestConfig::new("http://example.com:8080/path?q=1".to_string());
        let req = build_request(&uri, &config, true, true, None).unwrap();
        assert_eq!(req.uri(), "/path?q=1");
    }

    #[test]
    fn test_build_request_absolute_form_preserves_uri() {
        let uri: http::Uri = "http://example.com:8080/path?q=1".parse().unwrap();
        let config = RequestConfig::new("http://example.com:8080/path?q=1".to_string());
        let req = build_request(&uri, &config, false, false, None).unwrap();
        assert_eq!(req.uri().to_string(), "http://example.com:8080/path?q=1");
    }

    #[test]
    fn test_build_request_request_target_absolute_form() {
        // When request_target is set, the caller wants exact control.
        // Simulate: origin_form=false (as dispatch_direct does when request_target is Some)
        let uri: http::Uri = "http://evil.com/admin".parse().unwrap();
        let config = RequestConfig::new("http://example.com/".to_string());
        let req = build_request(&uri, &config, false, true, None).unwrap();
        assert_eq!(req.uri().to_string(), "http://evil.com/admin");
    }

    // ── Decompression ─────────────────────────────────────────────

    const NO_LIMIT: usize = 10 * 1024 * 1024;
    const SAMPLE: &[u8] = b"<html><body>hello hello hello</body></html>";

    fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Bare deflate, no zlib wrapper (RFC 1951).
    fn deflate_bytes(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// deflate inside a zlib wrapper (RFC 1950), which is what
    /// `Content-Encoding: deflate` is actually specified as.
    fn zlib_bytes(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn brotli_bytes(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    fn each_codec() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("gzip", gzip_bytes(SAMPLE)),
            ("deflate", deflate_bytes(SAMPLE)),
            ("br", brotli_bytes(SAMPLE)),
        ]
    }

    /// `decompress` reports both the bytes and whether they count as
    /// content. Most cases care about one or the other, so assert the
    /// classification here and hand back the part under test.
    fn decoded(encoding: &str, data: &[u8], max: usize) -> Vec<u8> {
        let out = decompress(encoding, data, max);
        assert!(
            out.decode_error.is_none(),
            "expected decoded content, got: {:?}",
            out.decode_error
        );
        out.body
    }

    fn undecoded(encoding: &str, data: &[u8], max: usize) -> (Vec<u8>, String) {
        let out = decompress(encoding, data, max);
        let reason = out
            .decode_error
            .expect("expected the body to be flagged as not fully decoded");
        (out.body, reason)
    }

    #[test]
    fn test_decompress_round_trips_every_codec() {
        for (encoding, compressed) in each_codec() {
            let out = decoded(encoding, &compressed, NO_LIMIT);
            assert_eq!(out, SAMPLE, "{} did not round-trip", encoding);
        }
    }

    #[test]
    fn test_decompress_accepts_both_deflate_flavors() {
        // RFC 9110 8.4.1.2 says `deflate` is a zlib stream, which is what
        // IIS and several CDN fronts send. Others send bare deflate. Only
        // handling one of the two hands back a compressed body as if it
        // were content, since neither decoder can read the other's input.
        for (flavor, compressed) in [
            ("zlib-wrapped", zlib_bytes(SAMPLE)),
            ("raw", deflate_bytes(SAMPLE)),
        ] {
            let out = decoded("deflate", &compressed, NO_LIMIT);
            assert_eq!(out, SAMPLE, "{} deflate did not round-trip", flavor);
        }
    }

    #[test]
    fn test_zlib_header_detection() {
        assert!(has_zlib_header(&zlib_bytes(SAMPLE)));
        // Default-compression zlib output starts 0x78 0x9c.
        assert!(has_zlib_header(&[0x78, 0x9c]));
        assert!(!has_zlib_header(&deflate_bytes(SAMPLE)));
        // Too short to carry a header, and not a header anyway.
        assert!(!has_zlib_header(b"x"));
        assert!(!has_zlib_header(b""));
        // Right method nibble, wrong check value.
        assert!(!has_zlib_header(&[0x78, 0x9d]));
    }

    #[test]
    fn test_decompress_deflate_falls_back_when_the_header_misleads() {
        // The zlib header check can match a raw stream by coincidence,
        // which is the whole reason for the fallback. Only one shape of raw
        // stream can collide: a non-final stored block, since the method
        // nibble pins the first three bits to BFINAL=0, BTYPE=00. Here a
        // stored block of 29 bytes lands on 0x08 0x1d, which also happens
        // to be a multiple of 31.
        let payload = b"twenty-nine bytes of content!";
        assert_eq!(payload.len(), 29, "test setup");
        let mut raw = vec![0x08, 0x1d, 0x00, 0xe2, 0xff];
        raw.extend_from_slice(payload);
        // Final, empty stored block to end the stream.
        raw.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);

        assert!(
            has_zlib_header(&raw),
            "test setup: these bytes must look like a zlib header"
        );
        let out = decoded("deflate", &raw, NO_LIMIT);
        assert_eq!(out, payload, "fallback to raw deflate didn't happen");
    }

    #[test]
    fn test_decompress_empty_body_yields_empty_not_error() {
        // Servers put a Content-Encoding on bodyless responses all the
        // time: any redirect with no body, a HEAD, a 304. There is no
        // stream to read, which is not a failure worth losing a
        // response over.
        for encoding in ["gzip", "deflate", "br"] {
            let out = decoded(encoding, b"", NO_LIMIT);
            assert!(out.is_empty(), "{} should yield an empty body", encoding);
        }
    }

    #[test]
    fn test_decompress_keeps_partial_output_from_a_truncated_stream() {
        // What `read_body`'s max_size cap produces: the compressed bytes
        // end mid-stream, so the rest was never going to arrive. Keep
        // whatever inflated rather than dropping the whole response.
        //
        // Flagged, though, when the format can tell. gzip ends with a CRC32
        // and a length, so a cut stream leaves a trailer that never arrives
        // and the decoder says so.
        let big = SAMPLE.repeat(400);
        let compressed = gzip_bytes(&big);
        let cut = &compressed[..compressed.len() / 2];
        let (out, reason) = undecoded("gzip", cut, NO_LIMIT);
        assert!(!out.is_empty(), "recovered nothing");
        assert!(
            big.starts_with(&out),
            "partial output should prefix the original"
        );
        assert!(
            reason.contains("did not decode cleanly"),
            "unexpected reason: {}",
            reason
        );
    }

    #[test]
    fn test_our_decoder_reads_a_cut_deflate_stream_as_a_short_one() {
        // The limit of the flag, pinned so its absence doesn't get read as a
        // guarantee. This is a property of the decoder, not of the format.
        // zlib (RFC 1950 §2.2) does carry an integrity trailer, a 4-byte
        // adler32, but `flate2`'s `ZlibDecoder` doesn't require it to be
        // present, so a truncated stream reads as a clean short one:
        //
        //   zlib, full                  Ok,  135000 bytes, matches
        //   zlib, trailer stripped (-4) Ok,  135000 bytes, matches
        //   zlib, adler32 corrupted     Err("corrupt deflate stream")
        //
        // Raw deflate (RFC 1951) has no trailer at all, so the same read is
        // the only one available to it. Damage mid-stream is still caught in
        // both flavors, since that produces an invalid block rather than a
        // tidy ending, and gzip catches truncation via its trailer.
        let big = SAMPLE.repeat(400);
        for (encoding, compressed) in [
            ("deflate", deflate_bytes(&big)),
            ("deflate", zlib_bytes(&big)),
        ] {
            let cut = &compressed[..compressed.len() / 2];
            let out = decoded(encoding, cut, NO_LIMIT);
            assert!(!out.is_empty());
            assert!(big.starts_with(&out));
            assert!(out.len() < big.len());
        }
    }

    #[test]
    fn test_a_corrupted_zlib_trailer_is_flagged() {
        // The other side of the test above: zlib's adler32 is checked when it
        // is present, so damage to it is caught even though truncation past
        // it is not. Without this, the pair above reads as "deflate has no
        // integrity check", which is a property of neither flavor.
        //
        // Whether the flag arrives as a failed or partial decode depends on
        // how much output cleared the decoder's buffer before the trailer was
        // reached, so this asserts that it is flagged and what the decoder
        // blamed, not which of the two shapes it took.
        let big = SAMPLE.repeat(400);
        let mut compressed = zlib_bytes(&big);
        let last = compressed.len() - 1;
        compressed[last] ^= 0xff;
        let (_, reason) = undecoded("deflate", &compressed, NO_LIMIT);
        assert!(
            reason.contains("corrupt deflate stream"),
            "unexpected reason: {}",
            reason
        );
    }

    #[test]
    fn test_output_cap_alone_is_not_a_decode_failure() {
        // The output cap ends the stream rather than breaking it, so a body
        // trimmed to `max_size` is still content. Worth pinning: if this
        // started reporting, every large compressed body on a capped request
        // would come back flagged.
        //
        // This holds only when the output cap is what ends the read. It is
        // reached first here because the fixture is ~200:1 compressible, so
        // 4096 bytes of output come off long before the compressed bytes run
        // out. See `test_capped_incompressible_body_is_flagged` for the case
        // where the same cap cuts the wire instead.
        let zeros = vec![0u8; 200_000];
        let out = decoded("gzip", &gzip_bytes(&zeros), 4096);
        assert_eq!(out.len(), 4096);
    }

    #[test]
    fn test_capped_incompressible_body_is_flagged() {
        // The other side of the cap: whether a capped body is flagged depends
        // on the body's entropy, because `max_body` bounds both the wire read
        // and the decoder output. On a barely-compressible body the wire is
        // cut first, the decoder runs out of input mid-stream, and that is
        // indistinguishable from truncation by a middlebox:
        //
        //   gzip, ~200:1 compressible, cap 50k   Ok,  out=50000
        //   gzip, incompressible,      cap 50k   Err("unexpected end of file")
        //
        // Flagged is the deliberate choice. A caller filtering on
        // `decode_error is None` drops these, which is the safe direction:
        // the alternative hands back a prefix that reads as a whole body.
        let mut incompressible = Vec::with_capacity(200_000);
        let mut state: u64 = 0x1234_5678;
        for _ in 0..200_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            incompressible.push((state >> 33) as u8);
        }
        let compressed = gzip_bytes(&incompressible);
        let cap = 50_000;
        let (out, reason) = undecoded("gzip", &compressed[..cap], cap);
        assert!(!out.is_empty(), "recovered nothing");
        assert!(
            incompressible.starts_with(&out),
            "partial output should prefix the original"
        );
        assert!(
            reason.contains("did not decode cleanly"),
            "unexpected reason: {}",
            reason
        );
    }

    #[test]
    fn test_decompress_truncated_brotli_recovers_nothing() {
        // brotli buffers a whole block before emitting, so a stream cut
        // partway usually yields no output at all and reports an error.
        // `parse_response` is what turns that into an empty body when the
        // cut was our own cap, since the status and headers are still
        // good. Pinned here because it is the reason that call-site
        // handling exists.
        let big = SAMPLE.repeat(400);
        let compressed = brotli_bytes(&big);
        let cut = &compressed[..compressed.len() / 2];
        let (body, reason) = undecoded("br", cut, NO_LIMIT);
        // The caller gets the bytes as they arrived, and something that
        // says they aren't content.
        assert_eq!(body, cut);
        assert!(
            reason.starts_with("brotli decompression failed"),
            "unexpected reason: {}",
            reason
        );
    }

    #[test]
    fn test_decompress_bounds_output_at_max_size() {
        // Compression ratios are unbounded, so the cap has to apply to
        // the inflated size. 200KB of zeros is a few hundred bytes on
        // the wire.
        let zeros = vec![0u8; 200_000];
        for (encoding, compressed) in [
            ("gzip", gzip_bytes(&zeros)),
            ("deflate", deflate_bytes(&zeros)),
            ("deflate", zlib_bytes(&zeros)),
            ("br", brotli_bytes(&zeros)),
        ] {
            assert!(compressed.len() < 1000, "{} test setup", encoding);
            let out = decoded(encoding, &compressed, 4096);
            assert_eq!(out.len(), 4096, "{} exceeded the cap", encoding);
        }
    }

    #[test]
    fn test_decompress_reports_a_body_that_doesnt_inflate() {
        // A body that isn't the encoding it claims yields no output at all.
        // The bytes still come back, but flagged, so a caller can't mistake
        // them for content.
        let (body, reason) = undecoded("gzip", b"this is not gzip", NO_LIMIT);
        assert_eq!(body, b"this is not gzip");
        assert!(
            reason.contains("decompression failed"),
            "unexpected reason: {}",
            reason
        );
    }

    #[test]
    fn test_decompress_flags_a_corrupt_stream() {
        // One bit flipped mid-stream still inflates a prefix, and the
        // decoder says so. Handing those bytes back as content means
        // anything that hashes, matches or diffs them is working on garbage
        // with nothing to tell it apart from a real body.
        let big = SAMPLE.repeat(400);
        let mut gz = gzip_bytes(&big);
        let mid = gz.len() / 2;
        gz[mid] ^= 0x01;

        let (body, reason) = undecoded("gzip", &gz, NO_LIMIT);
        assert!(!body.is_empty(), "test setup: expected a partial inflate");
        assert_ne!(body, big, "test setup: expected corrupted output");
        assert!(
            reason.contains("gzip"),
            "reason should name the codec: {}",
            reason
        );
    }

    #[test]
    fn test_decompress_flags_a_bad_checksum() {
        // gzip carries a CRC32, which is the only thing that catches a body
        // that inflated cleanly but isn't what was compressed. The bytes here
        // are fine, and the stream still says it was tampered with.
        let mut gz = gzip_bytes(SAMPLE);
        let n = gz.len();
        gz[n - 8] ^= 0x01;

        let (body, reason) = undecoded("gzip", &gz, NO_LIMIT);
        assert_eq!(body, SAMPLE);
        assert!(
            reason.contains("checksum") || reason.contains("gzip"),
            "unexpected reason: {}",
            reason
        );
    }

    #[test]
    fn test_decompress_passes_through_unknown_encoding() {
        let out = decoded("identity", SAMPLE, NO_LIMIT);
        assert_eq!(out, SAMPLE);
        // A coding we can't undo means the layers beneath it are out of
        // reach, so the body comes back exactly as it arrived, and says so.
        let gz = gzip_bytes(SAMPLE);
        for encoding in ["magic-codec", "gzip, magic-codec"] {
            let (body, reason) = undecoded(encoding, &gz, NO_LIMIT);
            assert_eq!(body, gz);
            assert!(
                reason.contains("magic-codec"),
                "reason should name the coding: {}",
                reason
            );
        }
    }

    #[test]
    fn test_decompress_accepts_the_x_gzip_alias() {
        // Deprecated, but servers still send it, and treating it as
        // unknown hands the caller compressed bytes as if they were the
        // body.
        let out = decoded("x-gzip", &gzip_bytes(SAMPLE), NO_LIMIT);
        assert_eq!(out, SAMPLE);
    }

    #[test]
    fn test_decompress_undoes_stacked_encodings_in_reverse() {
        // `Content-Encoding: gzip, br` means gzip was applied first and
        // brotli on top of it, so brotli comes off first.
        let stacked = brotli_bytes(&gzip_bytes(SAMPLE));
        assert_eq!(decoded("gzip, br", &stacked, NO_LIMIT), SAMPLE);
        // Whitespace around the list separator is normal.
        assert_eq!(decoded("gzip,br", &stacked, NO_LIMIT), SAMPLE);

        let three = deflate_bytes(&brotli_bytes(&gzip_bytes(SAMPLE)));
        assert_eq!(decoded("gzip, br, deflate", &three, NO_LIMIT), SAMPLE);

        // The same list arriving as repeated header lines is joined by
        // `parse_response` before it gets here, so this is the doubled
        // `Content-Encoding: gzip` case a proxy in front of a gzipping
        // backend produces.
        let twice = gzip_bytes(&gzip_bytes(SAMPLE));
        assert_eq!(decoded("gzip,gzip", &twice, NO_LIMIT), SAMPLE);
    }

    #[test]
    fn test_decompress_ignores_identity_entries_in_a_list() {
        let gz = gzip_bytes(SAMPLE);
        assert_eq!(decoded("identity, gzip", &gz, NO_LIMIT), SAMPLE);
        assert_eq!(decoded("gzip, identity", &gz, NO_LIMIT), SAMPLE);
    }

    #[test]
    fn test_decompress_ignores_empty_list_elements() {
        // RFC 9110 5.6.1.2 says to ignore these. They turn up from a
        // trailing comma, and from joining a repeated header line that
        // carried no value at all.
        let gz = gzip_bytes(SAMPLE);
        for encoding in ["gzip,", ",gzip", "gzip, ,", " , gzip"] {
            assert_eq!(decoded(encoding, &gz, NO_LIMIT), SAMPLE, "{}", encoding);
        }
    }

    #[test]
    fn test_decompress_bounds_output_of_stacked_encodings() {
        let zeros = vec![0u8; 200_000];
        let stacked = brotli_bytes(&gzip_bytes(&zeros));
        let out = decoded("gzip, br", &stacked, 4096);
        assert_eq!(out.len(), 4096);
    }

    #[test]
    fn test_decompress_reason_names_the_codec_that_failed() {
        let (_, reason) = undecoded("br", b"not brotli at all", NO_LIMIT);
        assert!(
            reason.starts_with("brotli decompression failed"),
            "unexpected reason: {}",
            reason
        );
    }

    #[test]
    fn test_decompress_returns_what_arrived_when_the_outermost_layer_fails() {
        // Declares `gzip, br`, so brotli comes off first, and only gzip was
        // applied. Nothing came off, so the caller gets exactly what
        // arrived, flagged.
        let gz = gzip_bytes(SAMPLE);
        let (body, _) = undecoded("gzip, br", &gz, NO_LIMIT);
        assert_eq!(body, gz);
    }

    #[test]
    fn test_decompress_keeps_the_deepest_peel_when_a_declared_layer_is_absent() {
        // A proxy that re-adds `Content-Encoding: gzip` in front of a
        // backend that already set it, without compressing again, sends two
        // header lines over a singly-compressed body. Reverting to the
        // original bytes there loses a body that reads fine, so keep the
        // deepest peel: one gzip came off and what's left is the content.
        let gz = gzip_bytes(SAMPLE);
        let (body, reason) = undecoded("gzip,gzip", &gz, NO_LIMIT);
        assert_eq!(body, SAMPLE);
        assert!(
            reason.starts_with("1 of 2 content-encoding layers came off"),
            "reason should say how far it got: {}",
            reason
        );

        // Same shape with different codings: br declared under a gzip that
        // did come off, but never applied.
        let (body, _) = undecoded("br, gzip", &gz, NO_LIMIT);
        assert_eq!(body, SAMPLE);
    }

    #[test]
    fn test_decompress_still_undoes_a_genuinely_doubled_encoding() {
        // The other reading of the same header, where both layers are
        // really there. This one decodes clean and isn't flagged.
        let twice = gzip_bytes(&gzip_bytes(SAMPLE));
        assert_eq!(decoded("gzip,gzip", &twice, NO_LIMIT), SAMPLE);
    }

    // ── Body reads ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_read_body_stops_reading_at_the_cap() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // A body that would be 10MB if read to the end, served 1KB at a
        // time. A 4KB cap has to stop asking for frames, not read it all
        // and then slice: an unbounded read is what lets a target exhaust
        // us while max_body_size looks like it's holding.
        let served = Arc::new(AtomicUsize::new(0));
        let counter = served.clone();
        let stream = futures::stream::iter((0..10_000).map(move |_| {
            counter.fetch_add(1, Ordering::Relaxed);
            Ok::<_, std::io::Error>(hyper::body::Frame::data(bytes::Bytes::from(vec![
                b'x';
                1024
            ])))
        }));

        let (body, cut) = read_body(http_body_util::StreamBody::new(stream), 4096)
            .await
            .unwrap();
        assert_eq!(body.len(), 4096);
        assert!(cut, "should report the cap cut the body");
        // Four frames of room, plus the one that overran it.
        let frames = served.load(Ordering::Relaxed);
        assert!(frames <= 5, "read {} frames past the cap", frames);
    }

    #[tokio::test]
    async fn test_read_body_ending_exactly_on_the_cap_is_not_cut() {
        // Length alone can't tell a truncated body from one that happens
        // to be exactly cap-sized, which is why the flag comes from the
        // read itself.
        let body = FullBody::new(bytes::Bytes::from(vec![b'x'; 4096]));
        let (out, cut) = read_body(body, 4096).await.unwrap();
        assert_eq!(out.len(), 4096);
        assert!(!cut);
    }

    #[tokio::test]
    async fn test_read_body_under_the_cap() {
        let body = FullBody::new(bytes::Bytes::from_static(SAMPLE));
        let (out, cut) = read_body(body, NO_LIMIT).await.unwrap();
        assert_eq!(out, SAMPLE);
        assert!(!cut);
    }
}
