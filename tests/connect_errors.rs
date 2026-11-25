//! A connect failure should say why it failed, on both the pooled path and the
//! direct one. hyper-util's own error reads "client error (Connect)" whatever
//! the cause, so these check that the cause underneath makes it out.

mod support;

use blasthttp::client::hyper::HyperClient;
use blasthttp::client::{ErrorKind, HttpClient, TlsFailure};
use blasthttp::config::RequestConfig;
use openssl::ssl::SslVersion;
use support::tls_server::{TlsServerConfig, TlsTestServer};
use tokio::net::TcpListener;

/// A local port with nothing listening on it.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

fn config_for(url: String) -> RequestConfig {
    let mut config = RequestConfig::new(url);
    config.timeout_seconds = Some(5);
    config.retries = Some(0);
    config
}

#[tokio::test]
async fn test_refused_connection_says_so_on_the_pooled_path() {
    let port = closed_port().await;
    let config = config_for(format!("http://127.0.0.1:{}/", port));

    let err = HyperClient::new().send(&config).await.unwrap_err();

    assert_eq!(err.kind, ErrorKind::Connection);
    assert!(
        err.message.to_lowercase().contains("refused"),
        "message should give the cause: {}",
        err.message
    );
}

#[tokio::test]
async fn test_refused_connection_says_so_on_the_direct_path() {
    let port = closed_port().await;
    let mut config = config_for(format!("http://localhost:{}/", port));
    // resolve_ip sends the request down the direct path
    config.resolve_ip = Some("127.0.0.1".to_string());

    let err = HyperClient::new().send(&config).await.unwrap_err();

    assert_eq!(err.kind, ErrorKind::Connection);
    assert!(
        err.message.to_lowercase().contains("refused"),
        "message should give the cause: {}",
        err.message
    );
}

#[tokio::test]
async fn test_an_earlier_tls_failure_does_not_relabel_a_later_error() {
    // A TLS failure belongs to the request that hit it. Once the server is
    // gone, the next request to the same host:port is refused, and that has
    // to read as a connection error (retryable), not as the old TLS failure.
    let server = TlsTestServer::start(TlsServerConfig {
        max_tls_version: Some(SslVersion::TLS1),
        ..Default::default()
    })
    .await;
    let mut config = config_for(server.url());
    config.verify_certs = Some(false);
    // Pinned at 1.2, so the handshake fails and nothing widens past it.
    config.min_tls_version = Some("1.2".to_string());

    let client = HyperClient::new();
    let first = client.send(&config).await.unwrap_err();
    assert_eq!(first.kind, ErrorKind::Tls, "setup: {}", first.message);
    assert!(first.tls_failure.is_some());

    server.shutdown().await;

    let second = client.send(&config).await.unwrap_err();
    assert_eq!(
        second.kind,
        ErrorKind::Connection,
        "a refused connection was reported as: {}",
        second.message
    );
    assert!(second.tls_failure.is_none());
}

/// Accepts connections, reads the ClientHello and hangs up. Counts how many
/// connections it saw.
async fn hangs_up_on_hello() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            drop(sock);
        }
    });
    (port, seen)
}

#[tokio::test]
async fn test_a_hangup_during_the_handshake_is_a_retryable_connection_error() {
    let (port, seen) = hangs_up_on_hello().await;
    let mut config = config_for(format!("https://127.0.0.1:{}/", port));
    config.retries = Some(1);
    config.retry_wait_min_ms = Some(10);
    config.retry_wait_max_ms = Some(10);

    let err = HyperClient::new().send(&config).await.unwrap_err();

    assert_eq!(err.kind, ErrorKind::Connection, "{}", err.message);
    assert_eq!(err.tls_failure, Some(TlsFailure::Reset));
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// Accepts connections and never answers them.
async fn silent_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(listener.accept().await.unwrap().0);
        }
    });
    port
}

#[tokio::test]
async fn test_a_handshake_timeout_reads_the_same_on_both_paths() {
    // A peer that accepts and never answers the ClientHello is a timeout on
    // the pooled path and the direct one alike.
    let port = silent_server().await;
    let mut seen = Vec::new();
    for direct in [false, true] {
        let mut config = config_for(format!("https://127.0.0.1:{}/", port));
        config.timeout_seconds = Some(1);
        if direct {
            config.resolve_ip = Some("127.0.0.1".to_string());
        }

        let err = HyperClient::new().send(&config).await.unwrap_err();

        assert_eq!(
            err.kind,
            ErrorKind::Timeout,
            "direct={direct}: {}",
            err.message
        );
        seen.push(err.tls_failure);
    }
    assert_eq!(seen[0], seen[1]);
}
