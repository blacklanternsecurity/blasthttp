//! The profile ladder, seen from the response a caller gets back.

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use blasthttp::report::{AttemptOutcome, Conclusion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Answers one connection with a Cloudflare challenge, then stops listening,
/// so every later connection to the port is refused.
async fn challenge_once() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        drop(listener);
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await;
        let body = "<html>Just a moment...</html>";
        let reply = format!(
            "HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\nserver: cloudflare\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = sock.write_all(reply.as_bytes()).await;
        let _ = sock.shutdown().await;
    });
    port
}

#[tokio::test]
async fn test_a_failed_escalation_keeps_the_refusal_it_had() {
    // A refusal moves the ladder on; if the next rung never gets a response,
    // the caller still gets the refusal, not the later error.
    let port = challenge_once().await;
    let mut config = RequestConfig::new(format!("http://127.0.0.1:{port}/"));
    config.timeout_seconds = Some(5);
    config.retries = Some(0);

    let resp = HyperClient::new()
        .send(&config)
        .await
        .unwrap_or_else(|e| panic!("the 403 was lost to: {}", e.message));

    assert_eq!(resp.status, 403);
    assert!(matches!(resp.conclusion(), Conclusion::NeedsBrowser { .. }));
    assert!(
        resp.attempts.len() >= 2,
        "the escalation should be recorded: {:?}",
        resp.attempts
    );
    assert!(matches!(
        resp.attempts[0].outcome,
        AttemptOutcome::Challenged { status: 403, .. }
    ));
    assert!(matches!(
        resp.attempts.last().unwrap().outcome,
        AttemptOutcome::HandshakeFailed { .. }
    ));
}
