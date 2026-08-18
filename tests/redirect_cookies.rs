//! End-to-end checks that cookies set mid-redirect reach the next hop.
//!
//! `ChainCookies` itself is unit-tested in `src/cookies.rs`; these tests prove the
//! wiring, i.e. that a real request through the client picks the cookie off
//! a 302 and puts it on the wire for the hop that follows.

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

/// Read one request's headers off a socket and hand back the raw lines.
fn read_request(stream: &mut TcpStream) -> Vec<String> {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            break;
        }
        lines.push(trimmed);
    }
    lines
}

/// Serve `/start` as a 302 to `/end` that sets a cookie, then serve `/end`.
/// Returns the port and a channel carrying the request lines for each hop.
fn spawn_server(set_cookie: &'static str) -> (u16, mpsc::Receiver<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        // Two hops: the redirect, then the destination. The client may open a
        // fresh connection for the second, so accept in a loop.
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let lines = read_request(&mut stream);
            let target = lines
                .first()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            let _ = tx.send(lines);

            let response = if target.ends_with("/start") {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: /end\r\nSet-Cookie: {}\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n",
                    set_cookie
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    (port, rx)
}

/// Like `spawn_server`, but the redirect carries `count` cookies of
/// `value_len` bytes each. Stays under hyper's 100-header default so the
/// response itself parses fine: the point is what we do with what it sets.
fn spawn_cookie_flood(count: usize, value_len: usize) -> (u16, mpsc::Receiver<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let lines = read_request(&mut stream);
            let target = lines
                .first()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            let _ = tx.send(lines);

            let response = if target.ends_with("/start") {
                let mut head = String::from("HTTP/1.1 302 Found\r\nLocation: /end\r\n");
                for i in 0..count {
                    head.push_str(&format!(
                        "Set-Cookie: c{}={}; Path=/\r\n",
                        i,
                        "A".repeat(value_len)
                    ));
                }
                head.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
                head
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    (port, rx)
}

/// The `Cookie` header the second hop received, if any.
fn second_hop_cookie(rx: &mpsc::Receiver<Vec<String>>) -> Option<String> {
    let _first = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("no first hop");
    let second = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("no second hop");
    second
        .iter()
        .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
        .map(|l| l[7..].trim().to_string())
}

async fn run(port: u16, mutate: impl FnOnce(&mut RequestConfig)) {
    let mut config = RequestConfig::new(format!("http://127.0.0.1:{}/start", port));
    config.follow_redirects = Some(true);
    mutate(&mut config);
    let client = HyperClient::new();
    let resp = client.send(&config).await.expect("request failed");
    assert_eq!(resp.status, 200, "should have landed on /end");
}

#[tokio::test]
async fn cookie_from_redirect_is_sent_on_the_next_hop() {
    let (port, rx) = spawn_server("session=abc123; Path=/");
    run(port, |_| {}).await;
    assert_eq!(second_hop_cookie(&rx).as_deref(), Some("session=abc123"));
}

#[tokio::test]
async fn opting_out_restores_the_old_behavior() {
    let (port, rx) = spawn_server("session=abc123; Path=/");
    run(port, |c| c.redirect_cookies = Some(false)).await;
    assert_eq!(second_hop_cookie(&rx), None);
}

#[tokio::test]
async fn secure_cookie_is_withheld_from_a_plaintext_hop() {
    let (port, rx) = spawn_server("session=abc123; Path=/; Secure");
    run(port, |_| {}).await;
    assert_eq!(second_hop_cookie(&rx), None);
}

#[tokio::test]
async fn cookie_scoped_to_another_path_is_not_sent() {
    let (port, rx) = spawn_server("session=abc123; Path=/somewhere-else");
    run(port, |_| {}).await;
    assert_eq!(second_hop_cookie(&rx), None);
}

#[tokio::test]
async fn cookie_for_an_unrelated_domain_is_rejected() {
    let (port, rx) = spawn_server("session=abc123; Domain=example.com");
    run(port, |_| {}).await;
    assert_eq!(second_hop_cookie(&rx), None);
}

#[tokio::test]
async fn chain_cookie_merges_with_a_caller_supplied_cookie_header() {
    let (port, rx) = spawn_server("session=abc123; Path=/");
    run(port, |c| {
        c.headers = Some(vec![("Cookie".to_string(), "mine=1".to_string())]);
    })
    .await;
    // One header carrying both, not two Cookie headers.
    assert_eq!(
        second_hop_cookie(&rx).as_deref(),
        Some("mine=1; session=abc123")
    );
}

#[tokio::test]
async fn caller_cookie_beats_one_the_chain_sets_under_the_same_name() {
    // The caller pinned `session`, the redirect tries to reset it. What they
    // set is what goes out, and it goes out once: sending both values would
    // land on whichever one the target's framework happens to read first.
    let (port, rx) = spawn_server("session=theirs; Path=/");
    run(port, |c| {
        c.headers = Some(vec![("Cookie".to_string(), "session=mine".to_string())]);
    })
    .await;
    assert_eq!(second_hop_cookie(&rx).as_deref(), Some("session=mine"));
}

#[tokio::test]
async fn chain_cookie_under_a_different_name_still_joins_the_callers() {
    // Only the names the caller claimed are off limits to the chain.
    let (port, rx) = spawn_server("csrf=xyz; Path=/");
    run(port, |c| {
        c.headers = Some(vec![("Cookie".to_string(), "session=mine".to_string())]);
    })
    .await;
    assert_eq!(
        second_hop_cookie(&rx).as_deref(),
        Some("session=mine; csrf=xyz")
    );
}

#[tokio::test]
async fn caller_cookie_survives_when_the_chain_adds_nothing() {
    let (port, rx) = spawn_server("bad; no-equals-sign");
    run(port, |c| {
        c.headers = Some(vec![("Cookie".to_string(), "mine=1".to_string())]);
    })
    .await;
    assert_eq!(second_hop_cookie(&rx).as_deref(), Some("mine=1"));
}

#[tokio::test]
async fn a_cookie_flood_cannot_grow_the_next_hop_without_bound() {
    // 90 cookies of 2KB is a legal response, and with no ceiling on what a
    // chain keeps, it made the next hop carry a 184,848 byte `Cookie`
    // header, with every further hop free to add more. The byte budget is
    // what keeps that bounded, and 8KB is about where servers stop accepting
    // a header line anyway.
    let (port, rx) = spawn_cookie_flood(90, 2048);
    run(port, |_| {}).await;
    let sent = second_hop_cookie(&rx).expect("second hop should still get cookies");
    assert!(
        sent.len() <= 8192,
        "second hop carried {} bytes of Cookie header",
        sent.len()
    );
    // Bounded, not empty: what the chain set first still goes out.
    assert!(sent.starts_with("c0="));
}
