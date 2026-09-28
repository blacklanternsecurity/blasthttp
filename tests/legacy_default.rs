// Full-stack tests: legacy ciphers and protocols must work WITHOUT the caller
// naming them.
//
// The custom OpenSSL build (scripts/build-openssl.sh, enable-weak-ssl-ciphers)
// exists so blasthttp can reach ancient servers. README.md advertises "All TLS
// ciphers available by default". These tests hold that promise to its word:
// every client config below sets `verify_certs` (the cert is self-signed) and
// a timeout, and nothing else. No `cipher_string`, no `min_tls_version`, no
// `max_tls_version`.
//
// Each test stands up a real TLS server pinned to one legacy cipher or
// protocol version, then makes a real request through the ordinary client
// path.

mod tls_server;

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use openssl::ssl::SslVersion;
use tls_server::{TlsServerConfig, TlsTestServer};

/// A client config with NO TLS tuning of any kind.
///
/// `verify_certs` is off because the test server's cert is self-signed, and
/// that is orthogonal to which ciphers we offer. Everything else is left at
/// the default, which is the entire point of these tests.
fn default_config(url: &str) -> RequestConfig {
    let mut config = RequestConfig::new(url.to_string());
    config.verify_certs = Some(false);
    config.timeout_seconds = Some(5);
    config
}

/// Stand up a server that speaks exactly one legacy cipher, then connect with
/// a stock client and assert we got the page.
async fn assert_reachable_with_cipher(cipher: &str) {
    let server = TlsTestServer::start(TlsServerConfig {
        cipher_list: Some(cipher.to_string()),
        // None of these ciphers exist in TLS 1.3, so the server has to sit at
        // 1.2 or below for the pin to mean anything.
        max_tls_version: Some(SslVersion::TLS1_2),
        ..Default::default()
    })
    .await;

    let config = default_config(&server.url());
    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(
        result.is_ok(),
        "a stock client should reach a {cipher}-only server, but got: {:?}",
        result.as_ref().err()
    );
    assert_eq!(result.unwrap().status, 200);

    server.shutdown().await;
}

/// Same, for a server pinned to one legacy protocol version.
async fn assert_reachable_with_version(label: &str, version: SslVersion) {
    let server = TlsTestServer::start(TlsServerConfig {
        min_tls_version: Some(version),
        max_tls_version: Some(version),
        ..Default::default()
    })
    .await;

    let config = default_config(&server.url());
    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(
        result.is_ok(),
        "a stock client should reach a {label}-only server, but got: {:?}",
        result.as_ref().err()
    );
    assert_eq!(result.unwrap().status, 200);

    server.shutdown().await;
}

// ── Legacy ciphers, no client configuration ───────────────────────

#[tokio::test]
async fn test_rc4_reachable_by_default() {
    assert_reachable_with_cipher("RC4-SHA").await;
}

#[tokio::test]
async fn test_rc4_md5_reachable_by_default() {
    assert_reachable_with_cipher("RC4-MD5").await;
}

#[tokio::test]
async fn test_3des_reachable_by_default() {
    assert_reachable_with_cipher("DES-CBC3-SHA").await;
}

#[tokio::test]
async fn test_seed_reachable_by_default() {
    assert_reachable_with_cipher("SEED-SHA").await;
}

#[tokio::test]
async fn test_camellia_reachable_by_default() {
    assert_reachable_with_cipher("CAMELLIA128-SHA").await;
}

#[tokio::test]
async fn test_anon_dh_reachable_by_default() {
    // Anonymous DH: no certificate at all. Worth reaching, since a server
    // that allows it is itself the finding.
    assert_reachable_with_cipher("ADH-AES128-SHA").await;
}

// ── Null encryption is deliberately NOT in the default ────────────

#[tokio::test]
async fn test_null_cipher_not_offered_by_default() {
    // A server offering only eNULL should be out of reach for a stock client.
    // Connecting would look like TLS while encrypting nothing, so it has to be
    // an explicit decision rather than something we fall into.
    let server = TlsTestServer::start(TlsServerConfig {
        cipher_list: Some("NULL-SHA".to_string()),
        max_tls_version: Some(SslVersion::TLS1_2),
        ..Default::default()
    })
    .await;

    let config = default_config(&server.url());
    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(
        result.is_err(),
        "null encryption must not be reachable without asking for it"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn test_null_cipher_reachable_when_asked_for() {
    // ...but naming it explicitly still works, so the capability is available
    // to anyone who actually wants it.
    let server = TlsTestServer::start(TlsServerConfig {
        cipher_list: Some("NULL-SHA".to_string()),
        max_tls_version: Some(SslVersion::TLS1_2),
        ..Default::default()
    })
    .await;

    let mut config = default_config(&server.url());
    config.cipher_string = Some("NULL-SHA".to_string());

    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(
        result.is_ok(),
        "explicit NULL-SHA should still connect: {:?}",
        result.as_ref().err()
    );

    server.shutdown().await;
}

// ── Legacy protocol versions, no client configuration ─────────────

#[tokio::test]
async fn test_tls10_reachable_by_default() {
    assert_reachable_with_version("TLS 1.0", SslVersion::TLS1).await;
}

#[tokio::test]
async fn test_tls11_reachable_by_default() {
    assert_reachable_with_version("TLS 1.1", SslVersion::TLS1_1).await;
}

// ── Control: this one already works, so a failure here means the
//    harness is broken rather than the client ──────────────────────

#[tokio::test]
async fn test_modern_still_reachable_by_default() {
    let server = TlsTestServer::start(TlsServerConfig {
        min_tls_version: Some(SslVersion::TLS1_2),
        ..Default::default()
    })
    .await;

    let config = default_config(&server.url());
    let client = HyperClient::new();
    let result = client.send(&config).await;

    assert!(
        result.is_ok(),
        "control case failed, so the harness is suspect: {:?}",
        result.as_ref().err()
    );

    server.shutdown().await;
}
