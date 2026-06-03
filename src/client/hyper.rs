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
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string());

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
        if let Ok(s) = entry.data().as_utf8() {
            emails.push(s.to_string());
        }
    }
    for entry in cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::PKCS9_EMAILADDRESS)
    {
        if let Ok(s) = entry.data().as_utf8()
            && !emails.contains(&s.to_string())
        {
            emails.push(s.to_string());
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
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string());

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
        builder
            .set_alpn_protos(b"\x02h2\x08http/1.1")
            .map_err(|e| ClientError::tls(format!("failed to set ALPN: {}", e)))?;

        let ssl = builder.build();
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        Ok(OpenSslConnector {
            http,
            ssl,
            cert_slot,
            peer_slot,
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

            let mut stream = tokio_openssl::SslStream::new(ssl_conf, tcp_stream)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            Pin::new(&mut stream)
                .connect()
                .await
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

/// Which connection mode to use for a given request.
#[derive(Clone, Hash, Eq, PartialEq)]
enum ConnMode {
    /// No proxy — connect directly to target.
    Direct,
    /// HTTP proxy + HTTP target — forward proxy (absolute-form URI to proxy).
    ForwardProxy(String),
    /// HTTP proxy + HTTPS target — CONNECT tunnel through proxy.
    Tunnel(String),
    /// SOCKS5 proxy — works for both HTTP and HTTPS targets.
    Socks5(String),
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
        match config.effective_proxy(target_uri.host().unwrap_or("")) {
            None => Ok(ConnMode::Direct),
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
                            Ok(ConnMode::Tunnel(proxy_url.to_string()))
                        } else {
                            Ok(ConnMode::ForwardProxy(proxy_url.to_string()))
                        }
                    }
                    "socks5" | "socks5h" => Ok(ConnMode::Socks5(proxy_url.to_string())),
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
            ConnMode::Direct => AnyClient::Direct(builder.build(connector)),
            ConnMode::ForwardProxy(_) => {
                // Forward proxy doesn't use a cached hyper Client — it dispatches
                // directly via http1::SendRequest in send_inner. This branch should
                // never be reached.
                unreachable!("ForwardProxy uses dispatch_forward_proxy, not get_or_build")
            }
            ConnMode::Tunnel(proxy_url) => {
                let proxy_uri: http::Uri =
                    proxy_url.parse().map_err(|e: http::uri::InvalidUri| {
                        ClientError::invalid_url(format!("invalid proxy URL: {}", e))
                    })?;
                use hyper_util::client::legacy::connect::proxy::Tunnel;
                let tunnel = Tunnel::new(proxy_uri, connector);
                AnyClient::Tunnel(builder.build(tunnel))
            }
            ConnMode::Socks5(proxy_url) => {
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
) -> Result<SingleResponse, ClientError> {
    // The pooled high-level client populates Host / :authority from the URI
    // itself, so we don't add a Host header here. Adding it would cause
    // duplicate :authority + host in the HTTP/2 HPACK block.
    let request = build_request(uri, config, false, false)?;
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

    let mut tcp = tokio::net::TcpStream::connect(&connect_addr)
        .await
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
                proxy::perform_http_connect(&mut tcp, &host, port).await?;
            }
            ProxyScheme::Socks5 => {
                proxy::perform_socks5(
                    &mut tcp,
                    &host,
                    port,
                    p.username.as_deref(),
                    p.password.as_deref(),
                )
                .await?;
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

    let mut tls_stream = tokio_openssl::SslStream::new(ssl_conf, tcp)
        .map_err(|e| ClientError::tls(format!("TLS stream setup failed: {}", e)))?;

    Pin::new(&mut tls_stream)
        .connect()
        .await
        .map_err(|e| ClientError::tls(format!("TLS handshake failed: {}", e)))?;

    let cert_info = extract_cert_info(tls_stream.ssl());
    let negotiated_alpn = tls_stream
        .ssl()
        .selected_alpn_protocol()
        .and_then(|b| std::str::from_utf8(b).ok().map(String::from));

    Ok((Box::new(tls_stream), cert_info, negotiated_alpn, peer_ip))
}

/// One-shot HTTP/1.1 request over a direct, un-pooled connection. Used when
/// `resolve_ip` or `request_target` is set and hyper's Client wrapper would
/// either normalize the URI (stripping absolute-form) or route through the
/// shared connection pool, neither of which matches the caller's intent for
/// these specialized requests (host_header, generic_ssrf, virtualhost
/// discovery).
async fn dispatch_direct(
    target_uri: &http::Uri,
    config: &RequestConfig,
    log: &DebugLog,
) -> Result<(SingleResponse, Option<CertInfo>, Option<IpAddr>), ClientError> {
    let v = config.verbosity;
    let (stream, cert_info, _alpn, peer_ip) = connect_stream(target_uri, config, log).await?;
    let io = hyper_util::rt::TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| ClientError::connection(format!("HTTP handshake failed: {}", e)))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

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
    let use_origin_form = config.request_target.is_none();
    let request = build_request(&request_uri, config, use_origin_form, true)?;

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
    let request = build_request(target_uri, config, false, true)?;
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

    if let Some(ref custom_headers) = config.headers {
        for (name, value) in custom_headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
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

    let content_encoding = hyper_response
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let max_body = config.max_body();
    let raw_bytes = read_body(hyper_response.into_body(), max_body).await?;
    debug_record(
        log,
        v,
        1,
        &format!("   Raw body: {} bytes", raw_bytes.len()),
    );

    let body_bytes = if content_encoding.is_empty() {
        raw_bytes
    } else {
        let decompressed = decompress(&content_encoding, &raw_bytes)?;
        debug_record(
            log,
            v,
            1,
            &format!(
                "   Decompressed ({}): {} -> {} bytes",
                content_encoding,
                raw_bytes.len(),
                decompressed.len()
            ),
        );
        decompressed
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
    })
}

struct SingleResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body_bytes: Vec<u8>,
    location: Option<String>,
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
                body_cache: std::sync::OnceLock::new(),
                raw_headers_cache: std::sync::OnceLock::new(),
                cookies_cache: std::sync::OnceLock::new(),
                hash_cache: std::sync::OnceLock::new(),
            });
        }

        let mut redirect_chain: Vec<RedirectHop> = Vec::new();
        let mut hops = 0u32;

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
                dispatch_forward_proxy(proxy_url, &uri, config, log).await?
            } else {
                dispatch_request(&cached.as_ref().unwrap().inner, &uri, config, log).await?
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
                body_cache: std::sync::OnceLock::new(),
                raw_headers_cache: std::sync::OnceLock::new(),
                cookies_cache: std::sync::OnceLock::new(),
                hash_cache: std::sync::OnceLock::new(),
            });
        }
    }
}

// ── Decompression ─────────────────────────────────────────────────

fn decompress(encoding: &str, data: &[u8]) -> Result<Vec<u8>, ClientError> {
    match encoding {
        "gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(data);
            let mut buf = Vec::new();
            decoder
                .read_to_end(&mut buf)
                .map_err(|e| ClientError::other(format!("gzip decompression failed: {}", e)))?;
            Ok(buf)
        }
        "deflate" => {
            let mut decoder = flate2::read::DeflateDecoder::new(data);
            let mut buf = Vec::new();
            decoder
                .read_to_end(&mut buf)
                .map_err(|e| ClientError::other(format!("deflate decompression failed: {}", e)))?;
            Ok(buf)
        }
        "br" => {
            let mut decoder = brotli::Decompressor::new(data, 4096);
            let mut buf = Vec::new();
            decoder
                .read_to_end(&mut buf)
                .map_err(|e| ClientError::other(format!("brotli decompression failed: {}", e)))?;
            Ok(buf)
        }
        _ => Ok(data.to_vec()),
    }
}

async fn read_body<B>(body: B, max_size: usize) -> Result<Vec<u8>, ClientError>
where
    B: hyper::body::Body<Data = bytes::Bytes>,
    B::Error: std::fmt::Display,
{
    let collected = body
        .collect()
        .await
        .map_err(|e| ClientError::connection(format!("failed to read body: {}", e)))?;

    let bytes = collected.to_bytes();

    if bytes.len() > max_size {
        Ok(bytes[..max_size].to_vec())
    } else {
        Ok(bytes.to_vec())
    }
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
        let req = build_request(&uri, &config, true, true).unwrap();
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
        let req = build_request(&uri, &config, false, false).unwrap();
        assert!(req.headers().get("host").is_none());
    }

    #[test]
    fn test_build_request_custom_host_overrides_auto() {
        let uri: http::Uri = "http://example.com:8080/path".parse().unwrap();
        let mut config = RequestConfig::new("http://example.com:8080/path".to_string());
        config.headers = Some(vec![("Host".to_string(), "custom.host".to_string())]);
        let req = build_request(&uri, &config, true, true).unwrap();
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
        let req = build_request(&uri, &config, false, false).unwrap();
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
        let req = build_request(&uri, &config, true, true).unwrap();
        let hosts: Vec<_> = req.headers().get_all("host").iter().collect();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], "first.host");
        assert_eq!(hosts[1], "second.host");
    }

    #[test]
    fn test_build_request_origin_form_strips_authority() {
        let uri: http::Uri = "http://example.com:8080/path?q=1".parse().unwrap();
        let config = RequestConfig::new("http://example.com:8080/path?q=1".to_string());
        let req = build_request(&uri, &config, true, true).unwrap();
        assert_eq!(req.uri(), "/path?q=1");
    }

    #[test]
    fn test_build_request_absolute_form_preserves_uri() {
        let uri: http::Uri = "http://example.com:8080/path?q=1".parse().unwrap();
        let config = RequestConfig::new("http://example.com:8080/path?q=1".to_string());
        let req = build_request(&uri, &config, false, false).unwrap();
        assert_eq!(req.uri().to_string(), "http://example.com:8080/path?q=1");
    }

    #[test]
    fn test_build_request_request_target_absolute_form() {
        // When request_target is set, the caller wants exact control.
        // Simulate: origin_form=false (as dispatch_direct does when request_target is Some)
        let uri: http::Uri = "http://evil.com/admin".parse().unwrap();
        let config = RequestConfig::new("http://example.com/".to_string());
        let req = build_request(&uri, &config, false, true).unwrap();
        assert_eq!(req.uri().to_string(), "http://evil.com/admin");
    }
}
