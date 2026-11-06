//! The profile ladder, seen from the response a caller gets back.

use blasthttp::client::hyper::HyperClient;
use blasthttp::client::{ErrorKind, HttpClient};
use blasthttp::config::RequestConfig;
use blasthttp::report::{AttemptOutcome, Conclusion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Answers one connection with `status`, `headers` and `body`, then stops
/// listening, so every later connection to the port is refused.
async fn serve_once(status: &str, headers: &str, body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let reply = format!(
        "HTTP/1.1 {status}\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        drop(listener);
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await;
        let _ = sock.write_all(reply.as_bytes()).await;
        let _ = sock.shutdown().await;
    });
    port
}

fn config(port: u16) -> RequestConfig {
    let mut config = RequestConfig::new(format!("http://127.0.0.1:{port}/"));
    config.timeout_seconds = Some(5);
    config.retries = Some(0);
    config
}

#[tokio::test]
async fn test_a_failed_escalation_keeps_the_refusal_it_had() {
    // A refusal moves the ladder on; if the next rung never gets a response,
    // the caller still gets the refusal, not the later error.
    let port = serve_once(
        "403 Forbidden",
        "cf-mitigated: challenge\r\nserver: cloudflare\r\n",
        "<html>Just a moment...</html>",
    )
    .await;

    let resp = HyperClient::new()
        .send(&config(port))
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

#[tokio::test]
async fn test_a_not_found_page_is_reached() {
    // A 404 is the server answering. It must not read as an unreachable host.
    let port = serve_once("404 Not Found", "server: nginx\r\n", "not found").await;

    let resp = HyperClient::new().send(&config(port)).await.unwrap();

    assert_eq!(resp.status, 404);
    assert_eq!(resp.conclusion(), Conclusion::Reached);
    assert_eq!(
        resp.attempts[0].outcome,
        AttemptOutcome::Reached { status: 404 }
    );
}

/// Answers the first connection with a Cloudflare challenge after `delay`,
/// then accepts every later connection and never answers it.
async fn slow_challenge_then_silence(delay: std::time::Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut first = true;
        let mut held = Vec::new();
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            if !first {
                held.push(sock);
                continue;
            }
            first = false;
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                tokio::time::sleep(delay).await;
                let body = "<html>Just a moment...</html>";
                let reply = format!(
                    "HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn test_an_escalation_that_runs_out_of_time_keeps_the_refusal() {
    // The refusal arrives most of the way through the timeout and the next
    // rung never answers. The caller gets the refusal, not a timeout.
    let port = slow_challenge_then_silence(std::time::Duration::from_millis(1500)).await;
    let mut config = config(port);
    config.timeout_seconds = Some(2);

    let resp = HyperClient::new()
        .send(&config)
        .await
        .unwrap_or_else(|e| panic!("the 403 was lost to: {}", e.message));

    assert_eq!(resp.status, 403);
    match &resp.attempts.last().unwrap().outcome {
        AttemptOutcome::HandshakeFailed { reason } => {
            assert!(reason.contains("timed out"), "{reason}")
        }
        other => panic!("the last rung should have timed out: {other:?}"),
    }
}

#[tokio::test]
async fn test_a_server_that_never_answers_still_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(listener.accept().await.unwrap().0);
        }
    });
    let mut config = config(port);
    config.timeout_seconds = Some(1);

    let err = HyperClient::new().send(&config).await.unwrap_err();

    assert_eq!(err.kind, ErrorKind::Timeout);
    assert_eq!(err.message, "request timed out after 1s");
}
