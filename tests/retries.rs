//! What the transport retries on its own, through `HyperClient::send`.
//!
//! A dropped connection is worth another try. So is a status in
//! `retry_statuses`, 429 by default, but only after waiting as long as the
//! server's `Retry-After` asks: a retry sooner is one more request the server
//! has already said it will refuse. Asked to wait longer than
//! `retry_wait_max_ms`, the transport hands the response back and lets the
//! caller decide.

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

fn read_request(stream: &TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
        line.clear();
    }
}

/// Answer the `n`th connection, counting from 1, with `respond(n)`, or drop it
/// unanswered when that is `None`. Returns the port and the count.
fn serve<F>(respond: F) -> (u16, Arc<AtomicUsize>)
where
    F: Fn(usize) -> Option<String> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let n = seen.fetch_add(1, Ordering::SeqCst) + 1;
            read_request(&stream);
            if let Some(response) = respond(n) {
                let _ = stream.write_all(response.as_bytes());
            }
        }
    });
    (port, count)
}

fn too_many(retry_after: Option<&str>) -> String {
    let header = retry_after
        .map(|v| format!("Retry-After: {v}\r\n"))
        .unwrap_or_default();
    format!(
        "HTTP/1.1 429 Too Many Requests\r\n{header}Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// One retry, a 10ms backoff, and room to wait up to 10s.
fn config(port: u16) -> RequestConfig {
    let mut c = RequestConfig::new(format!("http://127.0.0.1:{port}/"));
    c.timeout_seconds = Some(5);
    c.retries = Some(1);
    c.retry_wait_min_ms = Some(10);
    c.retry_wait_max_ms = Some(10_000);
    c
}

/// Send once, returning the status, how many requests the server saw, and how
/// long it took.
async fn send(config: RequestConfig, count: Arc<AtomicUsize>) -> (u16, usize, Duration) {
    let started = Instant::now();
    let r = HyperClient::new().send(&config).await.unwrap();
    (r.status, count.load(Ordering::SeqCst), started.elapsed())
}

#[tokio::test]
async fn test_a_429_is_retried_after_its_retry_after() {
    let (port, count) = serve(|n| {
        Some(if n == 1 {
            too_many(Some("1"))
        } else {
            OK.into()
        })
    });
    let (status, requests, took) = send(config(port), count).await;
    assert_eq!((status, requests), (200, 2));
    assert!(took >= Duration::from_millis(950), "retried after {took:?}");
}

#[tokio::test]
async fn test_a_retry_after_date_is_honored_too() {
    let at = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(2));
    let (port, count) = serve(move |n| {
        Some(if n == 1 {
            too_many(Some(&at))
        } else {
            OK.into()
        })
    });
    let (status, requests, took) = send(config(port), count).await;
    assert_eq!((status, requests), (200, 2));
    // An HTTP date has one-second resolution, so the wait is one to two seconds.
    assert!(took >= Duration::from_millis(900), "retried after {took:?}");
}

#[tokio::test]
async fn test_a_retry_after_over_the_max_wait_is_handed_back() {
    let (port, count) = serve(|_| Some(too_many(Some("30"))));
    let mut c = config(port);
    c.retry_wait_max_ms = Some(1000);
    let (status, requests, took) = send(c, count).await;
    assert_eq!((status, requests), (429, 1));
    assert!(
        took < Duration::from_secs(1),
        "waited {took:?} before handing it back"
    );
}

#[tokio::test]
async fn test_a_429_without_retry_after_takes_the_usual_backoff() {
    let (port, count) = serve(|n| Some(if n == 1 { too_many(None) } else { OK.into() }));
    let (status, requests, took) = send(config(port), count).await;
    assert_eq!((status, requests), (200, 2));
    assert!(took < Duration::from_millis(500), "took {took:?}");
}

#[tokio::test]
async fn test_retry_statuses_decides_what_is_retried() {
    for statuses in [vec![], vec![503]] {
        let (port, count) = serve(|_| Some(too_many(Some("1"))));
        let mut c = config(port);
        c.retry_statuses = Some(statuses.clone());
        let (status, requests, _) = send(c, count).await;
        assert_eq!((status, requests), (429, 1), "retry_statuses={statuses:?}");
    }
}

#[tokio::test]
async fn test_a_dropped_connection_is_retried() {
    let (port, count) = serve(|n| if n == 1 { None } else { Some(OK.into()) });
    for statuses in [None, Some(vec![])] {
        count.store(0, Ordering::SeqCst);
        let mut c = config(port);
        c.retry_statuses = statuses.clone();
        let (status, requests, _) = send(c, count.clone()).await;
        assert_eq!((status, requests), (200, 2), "retry_statuses={statuses:?}");
    }
}
