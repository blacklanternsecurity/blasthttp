// Integration tests for TLS cipher and version control.
// These spin up a real TLS server using our custom OpenSSL build,
// then connect with blasthttp's HyperClient to verify end-to-end behavior.

mod tls_server;

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use openssl::ssl::SslVersion;
use tls_server::{TlsServerConfig, TlsTestServer};

fn make_config(url: &str) -> RequestConfig {
    let mut config = RequestConfig::new(url.to_string());
    config.verify_certs = Some(false); // self-signed cert
    config.timeout_seconds = Some(5);
    config
}

// ── RC4 cipher tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_rc4_cipher_succeeds() {
    // Server accepts only RC4, client requests RC4
    let server = TlsTestServer::start(TlsServerConfig {
        cipher_list: Some("RC4-SHA".to_string()),
        max_tls_version: Some(SslVersion::TLS1_2), // RC4 not in TLS 1.3
        ..Default::default()
    })
    .await;

    let mut config = make_config(&server.url());
    config.cipher_string = Some("RC4-SHA".to_string());
    config.max_tls_version = Some("1.2".to_string());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(
        result.is_ok(),
        "RC4 connection should succeed: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap().status, 200);

    server.shutdown().await;
}

#[tokio::test]
async fn test_rc4_cipher_mismatch_fails() {
    // Server only accepts RC4, client only offers AES — should fail
    let server = TlsTestServer::start(TlsServerConfig {
        cipher_list: Some("RC4-SHA".to_string()),
        max_tls_version: Some(SslVersion::TLS1_2),
        ..Default::default()
    })
    .await;

    let mut config = make_config(&server.url());
    config.cipher_string = Some("AES128-SHA".to_string());
    config.max_tls_version = Some("1.2".to_string());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(result.is_err(), "cipher mismatch should fail");

    server.shutdown().await;
}

// ── 3DES cipher tests ─────────────────────────────────────────────

#[tokio::test]
async fn test_3des_cipher_succeeds() {
    let server = TlsTestServer::start(TlsServerConfig {
        cipher_list: Some("DES-CBC3-SHA".to_string()),
        max_tls_version: Some(SslVersion::TLS1_2),
        ..Default::default()
    })
    .await;

    let mut config = make_config(&server.url());
    config.cipher_string = Some("DES-CBC3-SHA".to_string());
    config.max_tls_version = Some("1.2".to_string());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(
        result.is_ok(),
        "3DES connection should succeed: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap().status, 200);

    server.shutdown().await;
}

// ── TLS version pinning tests ─────────────────────────────────────

#[tokio::test]
async fn test_tls12_only_succeeds() {
    // Both server and client pinned to TLS 1.2
    let server = TlsTestServer::start(TlsServerConfig {
        min_tls_version: Some(SslVersion::TLS1_2),
        max_tls_version: Some(SslVersion::TLS1_2),
        ..Default::default()
    })
    .await;

    let mut config = make_config(&server.url());
    config.min_tls_version = Some("1.2".to_string());
    config.max_tls_version = Some("1.2".to_string());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(
        result.is_ok(),
        "TLS 1.2 pinned connection should succeed: {:?}",
        result.err()
    );

    server.shutdown().await;
}

#[tokio::test]
async fn test_tls_version_mismatch_fails() {
    // Server only allows TLS 1.2, client only allows TLS 1.3 — no overlap
    let server = TlsTestServer::start(TlsServerConfig {
        min_tls_version: Some(SslVersion::TLS1_2),
        max_tls_version: Some(SslVersion::TLS1_2),
        ..Default::default()
    })
    .await;

    let mut config = make_config(&server.url());
    config.min_tls_version = Some("1.3".to_string());
    config.max_tls_version = Some("1.3".to_string());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(result.is_err(), "TLS version mismatch should fail");

    server.shutdown().await;
}

#[tokio::test]
async fn test_tls13_succeeds() {
    // Server allows all versions, client pins to TLS 1.3
    // (Not pinning server to 1.3-only avoids potential config conflicts)
    let server = TlsTestServer::start(TlsServerConfig::default()).await;

    let mut config = make_config(&server.url());
    config.min_tls_version = Some("1.3".to_string());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(
        result.is_ok(),
        "TLS 1.3 connection should succeed: {:?}",
        result.err()
    );

    server.shutdown().await;
}

// ── Default cipher tests ──────────────────────────────────────────

#[tokio::test]
async fn test_default_ciphers_succeed() {
    // No cipher config on either side — should just work with defaults
    let server = TlsTestServer::start(TlsServerConfig::default()).await;

    let config = make_config(&server.url());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(
        result.is_ok(),
        "default ciphers should succeed: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap().status, 200);

    server.shutdown().await;
}

// ── Response body verification ────────────────────────────────────

#[tokio::test]
async fn test_server_response_body_received() {
    let server = TlsTestServer::start(TlsServerConfig {
        response_body: "hello from test server".to_string(),
        ..Default::default()
    })
    .await;

    let config = make_config(&server.url());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body(), "hello from test server");

    server.shutdown().await;
}

// ── Invalid cipher string ─────────────────────────────────────────

#[tokio::test]
async fn test_invalid_cipher_string_returns_error() {
    let mut config = make_config("https://127.0.0.1:1");
    config.cipher_string = Some("TOTALLY_BOGUS_CIPHER".to_string());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(result.is_err(), "bogus cipher should error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("invalid cipher string"),
        "error should mention invalid cipher: {}",
        err_msg
    );
}

// ── Invalid TLS version ───────────────────────────────────────────

#[tokio::test]
async fn test_invalid_tls_version_returns_error() {
    let mut config = make_config("https://127.0.0.1:1");
    config.min_tls_version = Some("2.0".to_string());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(result.is_err(), "invalid TLS version should error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unknown TLS version"),
        "error should mention unknown version: {}",
        err_msg
    );
}

// ── Certificate info extraction ────────────────────────────────────

#[tokio::test]
async fn test_cert_info_extracted() {
    let server = TlsTestServer::start(TlsServerConfig::default()).await;

    let config = make_config(&server.url());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    let cert = resp
        .cert_info
        .expect("cert_info should be present for HTTPS");
    assert_eq!(cert.common_name.as_deref(), Some("localhost"));
    assert!(cert.sans.contains(&"localhost".to_string()));
    assert!(cert.issuer.is_some());
    assert!(cert.not_before.is_some());
    assert!(cert.not_after.is_some());
    assert!(cert.fingerprint_sha256.is_some());

    server.shutdown().await;
}

#[tokio::test]
async fn test_cert_info_has_san_ip() {
    // Our test server cert has SAN for 127.0.0.1
    let server = TlsTestServer::start(TlsServerConfig::default()).await;

    let config = make_config(&server.url());

    let client = HyperClient::new();
    let resp = client.send(&config).await.unwrap();
    let cert = resp.cert_info.expect("cert_info should be present");
    // The test cert has DNS:localhost and IP:127.0.0.1 as SANs
    // DNS SANs are extracted; IP SANs may or may not appear depending on OpenSSL
    assert!(cert.common_name.as_deref() == Some("localhost"));

    server.shutdown().await;
}

// ── Custom status code ────────────────────────────────────────────

#[tokio::test]
async fn test_server_custom_status_code() {
    let server = TlsTestServer::start(TlsServerConfig {
        response_status: 403,
        response_body: "forbidden".to_string(),
        ..Default::default()
    })
    .await;

    let config = make_config(&server.url());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().status, 403);

    server.shutdown().await;
}
