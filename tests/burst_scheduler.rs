// Does a burst against one host stop re-discovering that host once there is
// other work to get on with?
//
// The ladder trigger here is an RC4-only server rather than a protection
// product: a stock client offers `modern`, cannot negotiate, and widens to
// `compatibility`. Two attempts, visible in `Response::attempts`, and no
// vendor spoofing needed. What the scheduler does with them is the same
// either way.

mod support;

use blasthttp::batch::send_batch;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use openssl::ssl::SslVersion;
use std::sync::Arc;
use support::tls_server::{TlsServerConfig, TlsTestServer};

fn config(url: &str) -> RequestConfig {
    let mut c = RequestConfig::new(url.to_string());
    c.verify_certs = Some(false);
    c.timeout_seconds = Some(5);
    c
}

async fn legacy_server() -> TlsTestServer {
    TlsTestServer::start(TlsServerConfig {
        cipher_list: Some("RC4-SHA".to_string()),
        max_tls_version: Some(SslVersion::TLS1_2),
        ..Default::default()
    })
    .await
}

async fn modern_server() -> TlsTestServer {
    TlsTestServer::start(TlsServerConfig {
        min_tls_version: Some(SslVersion::TLS1_2),
        ..Default::default()
    })
    .await
}

fn attempts(results: &[blasthttp::batch::BatchResult], host: &str) -> usize {
    results
        .iter()
        .filter(|r| r.url.contains(host))
        .filter_map(|r| r.result.as_ref().ok())
        .map(|r| r.attempts.len())
        .sum()
}

fn reached(results: &[blasthttp::batch::BatchResult]) -> usize {
    results
        .iter()
        .filter(|r| r.result.as_ref().is_ok_and(|resp| resp.status == 200))
        .count()
}

#[tokio::test]
async fn test_a_burst_discovers_a_host_once_when_there_is_other_work() {
    let legacy = legacy_server().await;
    let modern = modern_server().await;

    let legacy_host = legacy.addr.port().to_string();
    let mut configs = Vec::new();
    for _ in 0..4 {
        configs.push(config(&legacy.url()));
    }
    for _ in 0..4 {
        configs.push(config(&modern.url()));
    }

    let client = Arc::new(HyperClient::new());
    let results = send_batch(client, configs, 8, None, None).await;

    assert_eq!(
        reached(&results),
        8,
        "every request should still get through"
    );

    // Four requests to a host needing a shift. Without the scheduler each
    // discovers it alone: 4 x 2 = 8 handshakes. With it, one discovers and
    // the other three are told: 2 + 3 = 5. Asserting on "fewer than eight"
    // rather than "exactly five" because the modern server's requests can
    // finish and free the other host before all four legacy ones have even
    // started, and how many get the news is a scheduling detail.
    let a = attempts(&results, &legacy_host);
    assert!(
        a < 8,
        "expected the burst to share what it learned, got {a} attempts for 4 requests"
    );
    assert!(
        a >= 5,
        "cannot be fewer than one discovery plus three, got {a}"
    );

    legacy.shutdown().await;
    modern.shutdown().await;
}

#[tokio::test]
async fn test_a_burst_with_nothing_else_to_do_does_not_wait() {
    // The case that killed the previous attempt. Every request wants the same
    // host, so standing aside would be standing idle, and the right answer is
    // to pay for the duplicate discovery instead. Four requests, two attempts
    // each, nobody waiting on anybody.
    let legacy = legacy_server().await;
    let legacy_host = legacy.addr.port().to_string();

    let configs: Vec<_> = (0..4).map(|_| config(&legacy.url())).collect();
    let client = Arc::new(HyperClient::new());

    let started = std::time::Instant::now();
    let results = send_batch(client, configs, 4, None, None).await;
    let elapsed = started.elapsed();

    assert_eq!(reached(&results), 4);
    assert_eq!(
        attempts(&results, &legacy_host),
        8,
        "with no other host to hand the slot to, every request discovers"
    );
    // Four concurrent local requests. If any of them had stood aside waiting
    // for another, this would be serial rather than parallel.
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "took {elapsed:?}, which means something waited"
    );

    legacy.shutdown().await;
}

#[tokio::test]
async fn test_a_host_that_cannot_be_reached_does_not_strand_the_rest() {
    // The leader guard marks the host answered when it drops, not when it
    // succeeds. Without that, a burst against a dead host would have one
    // request fail and the others sit on the stand-aside timeout.
    let modern = modern_server().await;
    let mut configs: Vec<_> = (0..4).map(|_| config("https://127.0.0.1:1/")).collect();
    configs.push(config(&modern.url()));

    let client = Arc::new(HyperClient::new());
    let started = std::time::Instant::now();
    let results = send_batch(client, configs, 5, None, None).await;
    let elapsed = started.elapsed();

    assert_eq!(results.len(), 5);
    assert_eq!(reached(&results), 1, "only the live server answers");
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "took {elapsed:?}: a failed leader should release the others at once"
    );

    modern.shutdown().await;
}
