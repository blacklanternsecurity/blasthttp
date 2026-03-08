use crate::config::RequestConfig;
use crate::debug::debug_print;
use crate::response::{Response, RedirectHop};
use super::{HttpClient, ClientError};

use std::io::Read;
use std::future::Future;
use std::pin::Pin;
use std::sync::Once;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

type FullBody = http_body_util::Full<bytes::Bytes>;

// Load the OpenSSL legacy provider once (for RC4, DES, etc.).
// The provider is statically compiled into libcrypto via `no-module` build flag.
// `Once` ensures this runs exactly once even across threads.
static INIT_LEGACY: Once = Once::new();

fn ensure_legacy_provider() {
    INIT_LEGACY.call_once(|| {
        // Load default provider first (required when explicitly loading providers)
        let _default = openssl::provider::Provider::try_load(None, "default", true)
            .expect("failed to load OpenSSL default provider");
        let _legacy = openssl::provider::Provider::try_load(None, "legacy", true)
            .expect("failed to load OpenSSL legacy provider");
        // Leak the providers so they stay loaded for the process lifetime
        std::mem::forget(_default);
        std::mem::forget(_legacy);
    });
}

// Custom HTTPS connector using OpenSSL directly.
// Wraps HttpConnector with TLS handshake via openssl + tokio-openssl.
#[derive(Clone)]
struct OpenSslConnector {
    http: HttpConnector,
    ssl: openssl::ssl::SslConnector,
}

fn parse_tls_version(s: &str) -> Result<openssl::ssl::SslVersion, ClientError> {
    match s.to_lowercase().as_str() {
        "1.0" | "tls1.0" | "tlsv1.0" => Ok(openssl::ssl::SslVersion::TLS1),
        "1.1" | "tls1.1" | "tlsv1.1" => Ok(openssl::ssl::SslVersion::TLS1_1),
        "1.2" | "tls1.2" | "tlsv1.2" => Ok(openssl::ssl::SslVersion::TLS1_2),
        "1.3" | "tls1.3" | "tlsv1.3" => Ok(openssl::ssl::SslVersion::TLS1_3),
        _ => Err(ClientError { message: format!("unknown TLS version '{}' (use 1.0, 1.1, 1.2, 1.3)", s) }),
    }
}

impl OpenSslConnector {
    fn new(config: &RequestConfig) -> Result<Self, ClientError> {
        // Ensure legacy ciphers (RC4, DES, etc.) are available
        ensure_legacy_provider();

        let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())
            .map_err(|e| ClientError { message: format!("SSL setup failed: {}", e) })?;

        if !config.should_verify_certs() {
            builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
        }

        if let Some(ref ciphers) = config.cipher_string {
            builder.set_cipher_list(ciphers)
                .map_err(|e| ClientError { message: format!("invalid cipher string '{}': {}", ciphers, e) })?;
        }

        if let Some(ref min_ver) = config.min_tls_version {
            let version = parse_tls_version(min_ver)?;
            builder.set_min_proto_version(Some(version))
                .map_err(|e| ClientError { message: format!("failed to set min TLS version: {}", e) })?;
        }

        if let Some(ref max_ver) = config.max_tls_version {
            let version = parse_tls_version(max_ver)?;
            builder.set_max_proto_version(Some(version))
                .map_err(|e| ClientError { message: format!("failed to set max TLS version: {}", e) })?;
        }

        let ssl = builder.build();
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        Ok(OpenSslConnector { http, ssl })
    }
}

// hyper-util's Client needs a Service<Uri> that returns an async connection.
// We implement this by connecting TCP first, then layering TLS on top.
// Newtype wrapper so we can impl Connection (orphan rule workaround)
struct SslStreamWrapper(tokio_openssl::SslStream<tokio::net::TcpStream>);

impl hyper::rt::Read for SslStreamWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Bridge through TokioIo
        let mut io = hyper_util::rt::TokioIo::new(&mut self.0);
        Pin::new(&mut io).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for SslStreamWrapper {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut io = hyper_util::rt::TokioIo::new(&mut self.0);
        Pin::new(&mut io).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut io = hyper_util::rt::TokioIo::new(&mut self.0);
        Pin::new(&mut io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut io = hyper_util::rt::TokioIo::new(&mut self.0);
        Pin::new(&mut io).poll_shutdown(cx)
    }
}

impl hyper_util::client::legacy::connect::Connection for SslStreamWrapper {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl Unpin for SslStreamWrapper {}

impl tower_service::Service<http::Uri> for OpenSslConnector {
    type Response = SslStreamWrapper;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(|e| Box::new(e) as _)
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let host = uri.host().unwrap_or("").to_string();
        let http_fut = self.http.call(uri);
        let ssl_connector = self.ssl.clone();

        Box::pin(async move {
            let tcp = http_fut.await?;
            let tcp_stream = tcp.into_inner();

            let mut ssl_conf = openssl::ssl::Ssl::new(ssl_connector.context())
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            ssl_conf.set_hostname(&host)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            let mut stream = tokio_openssl::SslStream::new(ssl_conf, tcp_stream)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            Pin::new(&mut stream).connect().await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            Ok(SslStreamWrapper(stream))
        })
    }
}

type DirectClient = Client<OpenSslConnector, FullBody>;
type HttpProxyClient = Client<
    hyper_util::client::legacy::connect::proxy::Tunnel<OpenSslConnector>,
    FullBody,
>;
type Socks5ProxyClient = Client<
    hyper_util::client::legacy::connect::proxy::SocksV5<OpenSslConnector>,
    FullBody,
>;

#[derive(Default)]
pub struct HyperClient;

impl HyperClient {
    pub fn new() -> Self {
        HyperClient
    }
}

enum AnyClient {
    Direct(DirectClient),
    HttpProxy(HttpProxyClient),
    Socks5(Socks5ProxyClient),
}

fn build_client(config: &RequestConfig) -> Result<AnyClient, ClientError> {
    let connector = OpenSslConnector::new(config)?;
    let builder = Client::builder(TokioExecutor::new());

    match config.proxy.as_deref() {
        None => Ok(AnyClient::Direct(builder.build(connector))),
        Some(proxy_url) => {
            let proxy_uri: http::Uri = proxy_url.parse().map_err(|e: http::uri::InvalidUri| {
                ClientError { message: format!("invalid proxy URL: {}", e) }
            })?;

            let scheme = proxy_uri.scheme_str().unwrap_or("");

            match scheme {
                "http" | "https" => {
                    use hyper_util::client::legacy::connect::proxy::Tunnel;
                    let tunnel = Tunnel::new(proxy_uri, connector);
                    Ok(AnyClient::HttpProxy(builder.build(tunnel)))
                }
                "socks5" | "socks5h" => {
                    use hyper_util::client::legacy::connect::proxy::SocksV5;
                    let socks = SocksV5::new(proxy_uri, connector);
                    Ok(AnyClient::Socks5(builder.build(socks)))
                }
                _ => Err(ClientError {
                    message: format!("unsupported proxy scheme '{}' (use http, https, socks5)", scheme),
                }),
            }
        }
    }
}

async fn dispatch_request(
    client: &AnyClient,
    uri: &http::Uri,
    config: &RequestConfig,
) -> Result<SingleResponse, ClientError> {
    let request = build_request(uri, config)?;
    let v = config.verbosity;

    debug_print(v, 1, "   Request headers:");
    for (name, value) in request.headers() {
        debug_print(v, 1, &format!("     {}: {}", name, value.to_str().unwrap_or("<binary>")));
    }
    debug_print(v, 1, "   Sending request...");

    let hyper_response = match client {
        AnyClient::Direct(c) => c.request(request).await,
        AnyClient::HttpProxy(c) => c.request(request).await,
        AnyClient::Socks5(c) => c.request(request).await,
    }.map_err(|e| ClientError {
        message: format!("request failed: {}", e),
    })?;

    parse_response(hyper_response, config).await
}

fn build_request(
    uri: &http::Uri,
    config: &RequestConfig,
) -> Result<hyper::Request<FullBody>, ClientError> {
    let mut builder = hyper::Request::builder()
        .method(config.method())
        .uri(uri)
        .header("User-Agent", "blasthttp/0.1.0")
        .header("Accept-Encoding", "gzip, deflate, br");

    if let Some(ref custom_headers) = config.headers {
        for (name, value) in custom_headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }

    let body_bytes = config.body.as_deref().unwrap_or("").as_bytes().to_vec();
    builder
        .body(http_body_util::Full::new(bytes::Bytes::from(body_bytes)))
        .map_err(|e| ClientError {
            message: format!("failed to build request: {}", e),
        })
}

async fn parse_response(
    hyper_response: hyper::Response<hyper::body::Incoming>,
    config: &RequestConfig,
) -> Result<SingleResponse, ClientError> {
    let v = config.verbosity;
    let status = hyper_response.status().as_u16();

    let location = hyper_response.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let mut headers: Vec<(String, String)> = Vec::new();
    debug_print(v, 1, "   Response headers:");
    for (name, value) in hyper_response.headers() {
        let val_str = value.to_str().unwrap_or("<binary>").to_string();
        debug_print(v, 1, &format!("     {}: {}", name, val_str));
        headers.push((name.to_string(), val_str));
    }

    let content_encoding = hyper_response.headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let max_body = config.max_body();
    let raw_bytes = read_body(hyper_response.into_body(), max_body).await?;
    debug_print(v, 1, &format!("   Raw body: {} bytes", raw_bytes.len()));

    let body_bytes = if content_encoding.is_empty() {
        raw_bytes
    } else {
        let decompressed = decompress(&content_encoding, &raw_bytes)?;
        debug_print(v, 1, &format!("   Decompressed ({}): {} -> {} bytes", content_encoding, raw_bytes.len(), decompressed.len()));
        decompressed
    };

    if body_bytes.len() >= max_body {
        debug_print(v, 1, &format!("   Body truncated at {} bytes", max_body));
    }

    Ok(SingleResponse { status, headers, body_bytes, location })
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
    if let Ok(uri) = location.parse::<http::Uri>()
        && uri.scheme().is_some()
    {
        return Ok(uri);
    }

    let scheme = current.scheme_str().unwrap_or("https");
    let authority = current.authority()
        .ok_or_else(|| ClientError {
            message: format!("no authority in current URL to resolve relative redirect: {}", location),
        })?;

    let absolute = format!("{}://{}{}", scheme, authority, location);
    absolute.parse().map_err(|e: http::uri::InvalidUri| ClientError {
        message: format!("invalid redirect URL '{}': {}", absolute, e),
    })
}

impl HttpClient for HyperClient {
    async fn send(&self, config: &RequestConfig) -> Result<Response, ClientError> {
        let timeout_duration = Duration::from_secs(config.timeout());

        tokio::time::timeout(timeout_duration, send_inner(config))
            .await
            .map_err(|_| ClientError {
                message: format!("request timed out after {}s", config.timeout()),
            })?
    }
}

async fn send_inner(config: &RequestConfig) -> Result<Response, ClientError> {
    let v = config.verbosity;
    let start = Instant::now();

    let mut uri: http::Uri = config.url.parse()
        .map_err(|e: http::uri::InvalidUri| ClientError {
            message: format!("invalid URL: {}", e),
        })?;

    debug_print(v, 1, &format!("-> {} {}", config.method(), uri));
    if let Some(ref proxy) = config.proxy {
        debug_print(v, 1, &format!("   Proxy: {}", proxy));
    }
    if !config.should_verify_certs() {
        debug_print(v, 1, "   TLS certificate validation: disabled");
    }
    if let Some(ref ciphers) = config.cipher_string {
        debug_print(v, 1, &format!("   Cipher string: {}", ciphers));
    }
    if let Some(ref min_ver) = config.min_tls_version {
        debug_print(v, 1, &format!("   Min TLS: {}", min_ver));
    }
    if let Some(ref max_ver) = config.max_tls_version {
        debug_print(v, 1, &format!("   Max TLS: {}", max_ver));
    }

    let client = build_client(config)?;
    let mut redirect_chain: Vec<RedirectHop> = Vec::new();
    let mut hops = 0u32;

    loop {
        let resp = dispatch_request(&client, &uri, config).await?;
        let hop_ms = start.elapsed().as_millis();
        debug_print(v, 1, &format!("<- {} ({}ms)", resp.status, hop_ms));

        if is_redirect(resp.status) && config.should_follow_redirects() {
            hops += 1;
            if hops > config.redirect_limit() {
                return Err(ClientError {
                    message: format!("too many redirects (limit: {})", config.redirect_limit()),
                });
            }

            let location = resp.location.as_deref()
                .ok_or_else(|| ClientError {
                    message: format!("redirect {} but no Location header", resp.status),
                })?;

            let next_uri = resolve_redirect(&uri, location)?;
            debug_print(v, 1, &format!("   Redirect #{}: {} -> {}", hops, uri, next_uri));

            redirect_chain.push(RedirectHop {
                url: uri.to_string(),
                status: resp.status,
            });

            uri = next_uri;
            continue;
        }

        let body = String::from_utf8(resp.body_bytes.clone())
            .unwrap_or_else(|_| String::from_utf8_lossy(&resp.body_bytes).to_string());

        let elapsed_ms = start.elapsed().as_millis() as u64;
        debug_print(v, 1, &format!("   Total time: {}ms ({} redirect(s))", elapsed_ms, redirect_chain.len()));

        return Ok(Response {
            url: uri.to_string(),
            status: resp.status,
            headers: resp.headers,
            body_bytes: resp.body_bytes,
            body,
            elapsed_ms,
            redirect_chain,
        });
    }
}

fn decompress(encoding: &str, data: &[u8]) -> Result<Vec<u8>, ClientError> {
    match encoding {
        "gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(data);
            let mut buf = Vec::new();
            decoder.read_to_end(&mut buf).map_err(|e| ClientError {
                message: format!("gzip decompression failed: {}", e),
            })?;
            Ok(buf)
        }
        "deflate" => {
            let mut decoder = flate2::read::DeflateDecoder::new(data);
            let mut buf = Vec::new();
            decoder.read_to_end(&mut buf).map_err(|e| ClientError {
                message: format!("deflate decompression failed: {}", e),
            })?;
            Ok(buf)
        }
        "br" => {
            let mut decoder = brotli::Decompressor::new(data, 4096);
            let mut buf = Vec::new();
            decoder.read_to_end(&mut buf).map_err(|e| ClientError {
                message: format!("brotli decompression failed: {}", e),
            })?;
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
    let collected = body.collect().await
        .map_err(|e| ClientError {
            message: format!("failed to read body: {}", e),
        })?;

    let bytes = collected.to_bytes();

    if bytes.len() > max_size {
        Ok(bytes[..max_size].to_vec())
    } else {
        Ok(bytes.to_vec())
    }
}
