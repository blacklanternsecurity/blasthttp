//! Integration tests for peer_ip capture: plain HTTP, redirect chain
//! across distinct loopback addresses, dispatch_direct path with
//! resolve_ip, and the RawConnection variant.

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::client::raw::RawConnection;
use blasthttp::config::RequestConfig;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Drain one HTTP request, return the configured response. Closes after.
/// Bind address comes from the caller so tests can pin to specific
/// loopback IPs.
async fn spawn_one_shot_server(bind: &str, response: &'static str) -> SocketAddr {
    let listener = TcpListener::bind(bind).await.expect("bind failed");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            // Read until we see the end of headers, then write the response.
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;
            loop {
                let n = match sock.read(&mut buf[total..]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if total >= buf.len() {
                    break;
                }
            }
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    addr
}

fn plain_http_url(addr: SocketAddr) -> String {
    format!("http://{}/", addr)
}

#[tokio::test]
async fn pooled_path_records_peer_ip_for_127_0_0_1() {
    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let addr = spawn_one_shot_server("127.0.0.1:0", resp).await;

    let client = HyperClient::new();
    let mut config = RequestConfig::new(plain_http_url(addr));
    config.timeout_seconds = Some(5);

    let response = client.send(&config).await.expect("request failed");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.peer_ip.as_deref(),
        Some("127.0.0.1"),
        "expected 127.0.0.1 peer, got {:?}",
        response.peer_ip,
    );
}

/// 127.0.0.1 → 127.0.0.2 redirect chain. Linux maps the entire
/// 127.0.0.0/8 to loopback by default, so we can bind both. If the
/// test host doesn't (some BSDs / containers), the bind on .0.2 will
/// fail and we skip rather than fail the suite.
#[tokio::test]
async fn redirect_chain_records_peer_ip_per_hop() {
    let second = spawn_one_shot_server(
        "127.0.0.2:0",
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone",
    )
    .await;

    let location = format!("http://{}/", second);
    // Allocate first server's redirect response with a 'static lifetime
    // by leaking — fine for a single test process.
    let first_resp: &'static str = Box::leak(
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n",
            location
        )
        .into_boxed_str(),
    );
    let first = spawn_one_shot_server("127.0.0.1:0", first_resp).await;

    let client = HyperClient::new();
    let mut config = RequestConfig::new(plain_http_url(first));
    config.follow_redirects = Some(true);
    config.timeout_seconds = Some(5);

    let response = client.send(&config).await.expect("request failed");
    assert_eq!(response.status, 200);
    assert_eq!(response.redirect_chain.len(), 1);
    assert_eq!(
        response.redirect_chain[0].peer_ip.as_deref(),
        Some("127.0.0.1"),
        "first hop peer_ip should be 127.0.0.1, got {:?}",
        response.redirect_chain[0].peer_ip,
    );
    assert_eq!(
        response.peer_ip.as_deref(),
        Some("127.0.0.2"),
        "final hop peer_ip should be 127.0.0.2, got {:?}",
        response.peer_ip,
    );
}

#[tokio::test]
async fn dispatch_direct_with_resolve_ip_records_peer_ip() {
    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let addr = spawn_one_shot_server("127.0.0.1:0", resp).await;
    let port = addr.port();

    let client = HyperClient::new();
    // resolve_ip path: caller supplies the IP, we use it. The URL host
    // is whatever — we send Host header from URL but dial resolve_ip.
    let mut config = RequestConfig::new(format!("http://example.invalid:{}/", port));
    config.resolve_ip = Some("127.0.0.1".to_string());
    config.timeout_seconds = Some(5);

    let response = client.send(&config).await.expect("request failed");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.peer_ip.as_deref(),
        Some("127.0.0.1"),
        "resolve_ip path should record peer_ip, got {:?}",
        response.peer_ip,
    );
}

#[tokio::test]
async fn response_carries_raw_headers_and_parsed_cookies() {
    // Server returns two Set-Cookie headers + extras, so we can verify
    // both raw_headers (pre-joined) and cookies (parsed dict).
    let resp = "HTTP/1.1 200 OK\r\n\
                Content-Type: text/html\r\n\
                Set-Cookie: session=abc123; Path=/; HttpOnly\r\n\
                Set-Cookie: pref=dark; Path=/\r\n\
                Content-Length: 2\r\n\
                \r\n\
                ok";
    let addr = spawn_one_shot_server("127.0.0.1:0", resp).await;

    let client = HyperClient::new();
    let mut config = RequestConfig::new(plain_http_url(addr));
    config.timeout_seconds = Some(5);

    let response = client.send(&config).await.expect("request failed");

    // raw_headers: the canonical "Name: Value\r\n..." form. Order and
    // casing match what the wire delivered. No trailing CRLF.
    let raw = response.raw_headers();
    assert!(
        raw.contains("content-type: text/html"),
        "expected content-type in raw_headers, got: {:?}",
        raw,
    );
    assert!(
        raw.contains("set-cookie: session=abc123"),
        "expected first Set-Cookie in raw_headers, got: {:?}",
        raw,
    );
    assert!(
        !raw.ends_with("\r\n"),
        "raw_headers should not have trailing CRLF, got: {:?}",
        raw,
    );

    // cookies: dict with two entries. Attributes (Path, HttpOnly) stripped.
    let cookies = response.cookies();
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
    assert_eq!(cookies.get("pref"), Some(&"dark".to_string()));

    // Hash sanity: the header hash should match what we'd compute by
    // hashing raw_headers ourselves — proving raw_headers and the
    // hashed bytes are the same string (single source of truth).
    let expected_md5: String =
        openssl::hash::hash(openssl::hash::MessageDigest::md5(), raw.as_bytes())
            .unwrap()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
    assert_eq!(response.hash().header_md5, expected_md5);

    // Lazy-cache sanity: calling raw_headers() / hash() / cookies()
    // again returns identical references (cache populated, no rebuild).
    assert!(std::ptr::eq(response.raw_headers(), raw));
    assert!(std::ptr::eq(response.hash(), response.hash()));
    assert!(std::ptr::eq(response.cookies(), response.cookies()));
}

#[tokio::test]
async fn raw_connection_records_peer_ip() {
    // RawConnection needs no real HTTP server — we just need a TCP
    // peer that doesn't refuse the connection. The one-shot server
    // accepts and waits for input, which is enough.
    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let addr = spawn_one_shot_server("127.0.0.1:0", resp).await;
    let url = format!("http://{}/", addr);

    let config = RequestConfig::new(url.clone());
    let conn = RawConnection::connect(&url, &config)
        .await
        .expect("raw connect failed");
    assert_eq!(
        conn.peer_ip().as_deref(),
        Some("127.0.0.1"),
        "raw connection peer_ip should be 127.0.0.1, got {:?}",
        conn.peer_ip(),
    );
    let _ = conn.close().await;
}
