use crate::config::RequestConfig;
use crate::debug::debug_print;
use crate::response::{Response, RedirectHop};
use super::{HttpClient, ClientError};

use std::io::Read;
use std::time::{Duration, Instant};
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

type HttpsConnector = hyper_tls::HttpsConnector<HttpConnector>;
type FullBody = http_body_util::Full<bytes::Bytes>;

type DirectClient = Client<HttpsConnector, FullBody>;
type HttpProxyClient = Client<
    hyper_util::client::legacy::connect::proxy::Tunnel<HttpsConnector>,
    FullBody,
>;
type Socks5ProxyClient = Client<
    hyper_util::client::legacy::connect::proxy::SocksV5<HttpsConnector>,
    FullBody,
>;

#[derive(Default)]
pub struct HyperClient;

impl HyperClient {
    pub fn new() -> Self {
        HyperClient
    }
}

fn build_https_connector(config: &RequestConfig) -> Result<HttpsConnector, ClientError> {
    let mut tls_builder = native_tls::TlsConnector::builder();
    if !config.should_verify_certs() {
        tls_builder.danger_accept_invalid_certs(true);
        tls_builder.danger_accept_invalid_hostnames(true);
    }
    let native_tls_connector = tls_builder.build().map_err(|e| ClientError {
        message: format!("TLS setup failed: {}", e),
    })?;

    let tokio_tls: tokio_native_tls::TlsConnector = native_tls_connector.into();
    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    Ok(hyper_tls::HttpsConnector::from((http_connector, tokio_tls)))
}

enum AnyClient {
    Direct(DirectClient),
    HttpProxy(HttpProxyClient),
    Socks5(Socks5ProxyClient),
}

fn build_client(config: &RequestConfig) -> Result<AnyClient, ClientError> {
    let https = build_https_connector(config)?;
    let builder = Client::builder(TokioExecutor::new());

    match config.proxy.as_deref() {
        None => Ok(AnyClient::Direct(builder.build(https))),
        Some(proxy_url) => {
            let proxy_uri: http::Uri = proxy_url.parse().map_err(|e: http::uri::InvalidUri| {
                ClientError { message: format!("invalid proxy URL: {}", e) }
            })?;

            let scheme = proxy_uri.scheme_str().unwrap_or("");

            match scheme {
                "http" | "https" => {
                    use hyper_util::client::legacy::connect::proxy::Tunnel;
                    let tunnel = Tunnel::new(proxy_uri, https);
                    Ok(AnyClient::HttpProxy(builder.build(tunnel)))
                }
                "socks5" | "socks5h" => {
                    use hyper_util::client::legacy::connect::proxy::SocksV5;
                    let socks = SocksV5::new(proxy_uri, https);
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
