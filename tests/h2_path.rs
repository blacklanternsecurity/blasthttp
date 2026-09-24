//! What the client sends as `:path` over HTTP/2.
//!
//! hyper builds `:path` from the request URI's path-and-query as written, so
//! a URL with no path (`https://host?q=1`) has to be given one before it gets
//! there. Servers reject `:path: ?q=1` with a 400.

#[allow(dead_code)]
mod tls_server;

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tls_server::{TlsServerConfig, build_h2_acceptor};
use tokio::net::TcpListener;

/// Serve HTTP/2 over TLS until the test ends, recording every `:path` that
/// arrives. Like a strict server, answer 400 to one that doesn't start with
/// `/`. `/redirect` sends the client to a URL on this server with no path.
async fn spawn_h2_server() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let acceptor = build_h2_acceptor(&TlsServerConfig::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let seen = paths.clone();

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut tls = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
            if std::pin::Pin::new(&mut tls).accept().await.is_err() {
                continue;
            }
            let seen = seen.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req: hyper::Request<_>| {
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|pq| pq.as_str().to_string())
                        .unwrap_or_default();
                    seen.lock().unwrap().push(path.clone());
                    let resp = if !path.starts_with('/') {
                        hyper::Response::builder().status(400)
                    } else if path == "/redirect" {
                        hyper::Response::builder()
                            .status(302)
                            .header("location", format!("https://{}?from=redirect", addr))
                    } else {
                        hyper::Response::builder().status(200)
                    };
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            resp.body(Full::new(Bytes::from_static(b"ok"))).unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    (addr, paths)
}

fn h2_config(url: String) -> RequestConfig {
    let mut config = RequestConfig::new(url);
    config.verify_certs = Some(false); // self-signed cert
    config.timeout_seconds = Some(5);
    config.alpn_protocols = Some(vec!["h2".to_string()]);
    config
}

#[tokio::test]
async fn url_with_no_path_is_sent_with_a_leading_slash() {
    let (addr, paths) = spawn_h2_server().await;
    let config = h2_config(format!("https://{}?q=%25.example.com", addr));

    let resp = HyperClient::new()
        .send(&config)
        .await
        .expect("request failed");

    assert_eq!(*paths.lock().unwrap(), vec!["/?q=%25.example.com"]);
    assert_eq!(resp.status, 200);
}

#[tokio::test]
async fn redirect_to_a_url_with_no_path_is_sent_with_a_leading_slash() {
    let (addr, paths) = spawn_h2_server().await;
    let mut config = h2_config(format!("https://{}/redirect", addr));
    config.follow_redirects = Some(true);

    let resp = HyperClient::new()
        .send(&config)
        .await
        .expect("request failed");

    assert_eq!(*paths.lock().unwrap(), vec!["/redirect", "/?from=redirect"]);
    assert_eq!(resp.status, 200);
}
