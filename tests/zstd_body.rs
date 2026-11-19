//! `Content-Encoding: zstd` through `HyperClient::send`, from the wire to the
//! body a caller reads. The decoder itself is unit-tested in `hyper.rs`; these
//! prove the response path hands it the body and keeps what it returns.

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use blasthttp::response::Response;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

fn zstd(data: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
}

/// Bytes that barely compress, from a fixed seed so a failure reproduces.
fn incompressible(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Answer one request with `body`, declared as zstd.
fn serve(body: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
            line.clear();
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-encoding: zstd\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
    });
    port
}

async fn fetch(body: Vec<u8>, max_body_size: Option<usize>) -> Response {
    let port = serve(body);
    let mut config = RequestConfig::new(format!("http://127.0.0.1:{port}/"));
    config.timeout_seconds = Some(5);
    config.max_body_size = max_body_size;
    HyperClient::new()
        .send(&config)
        .await
        .expect("request failed")
}

#[tokio::test]
async fn test_a_zstd_body_is_decoded() {
    let page = b"<html><body>hello</body></html>".repeat(20);
    let r = fetch(zstd(&page), None).await;
    assert_eq!(r.body_bytes, page);
    assert_eq!(r.decode_error, None);
}

#[tokio::test]
async fn test_every_frame_of_a_zstd_body_is_decoded() {
    let mut body = zstd(b"first ");
    body.extend(zstd(b"second"));
    let r = fetch(body, None).await;
    assert_eq!(r.body_bytes, b"first second");
    assert_eq!(r.decode_error, None);
}

#[tokio::test]
async fn test_a_zstd_body_is_bounded_by_max_body_size() {
    // Small on the wire, large decoded: the cap bounds the output, and the
    // stream reads clean up to it.
    let r = fetch(zstd(&vec![0u8; 200_000]), Some(4096)).await;
    assert_eq!(r.body_bytes.len(), 4096);
    assert_eq!(r.decode_error, None);
}

#[tokio::test]
async fn test_a_zstd_body_cut_on_the_wire_is_flagged() {
    // About as large on the wire as decoded, so the cap ends the read inside
    // the frame. Whatever comes back, it must not pass for content.
    let r = fetch(zstd(&incompressible(200_000)), Some(4096)).await;
    assert!(r.body_bytes.len() <= 4096);
    let reason = r
        .decode_error
        .expect("a body cut mid-frame must be flagged");
    assert!(
        reason.contains("zstd") && reason.contains("max_body"),
        "reason should name the codec and the cap: {reason}"
    );
}
