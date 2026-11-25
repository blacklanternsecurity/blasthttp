// A TLS bisect sends the default profile's ClientHello, whatever profile was
// asked for. Its own binary, since the bisect is a process-wide variable.

mod support;

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use support::tls_server::{CapturedHello, TlsServerConfig, TlsTestServer};

/// Capture the extensions of one hello, on the pooled path or, with
/// `resolve_ip`, the direct one.
async fn capture(profile: &str, direct: bool) -> Vec<u16> {
    let server = TlsTestServer::start(TlsServerConfig::default()).await;
    let mut config = RequestConfig::new(format!("https://localhost:{}/", server.addr.port()));
    config.verify_certs = Some(false);
    config.timeout_seconds = Some(5);
    config.profile = Some(profile.to_string());
    if direct {
        config.resolve_ip = Some("127.0.0.1".to_string());
    }

    let _ = HyperClient::new().send(&config).await;

    let hello: CapturedHello = server
        .hello
        .lock()
        .expect("hello slot poisoned")
        .clone()
        .expect("server recorded no ClientHello");
    server.shutdown().await;
    let mut extensions = hello.extensions;
    extensions.sort_unstable();
    extensions
}

#[tokio::test]
async fn test_tls_bisect_sends_the_default_hello() {
    // SAFETY: the only test in this binary, set before any request is made.
    unsafe { std::env::set_var("BLASTHTTP_BISECT", "tls") };

    for direct in [false, true] {
        let chrome = capture("chrome131", direct).await;
        let modern = capture("modern", direct).await;
        assert!(
            !chrome.contains(&0x0005),
            "status_request sent under a TLS bisect (direct={direct}): {chrome:04x?}"
        );
        assert_eq!(chrome, modern, "direct={direct}");
    }
}
