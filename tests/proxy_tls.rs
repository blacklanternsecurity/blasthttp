//! HTTPS through a proxy has to be TLS to the target, carried inside the
//! tunnel the proxy opens. These tests run a small CONNECT proxy and a small
//! SOCKS5 proxy in front of the TLS test server, and look at the first byte
//! that goes through the tunnel: a TLS handshake starts with 0x16, and a
//! plaintext request starts with the method.

#[allow(dead_code)]
mod tls_server;

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use std::sync::{Arc, Mutex};
use tls_server::{TlsServerConfig, TlsTestServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The first TLS record type: a handshake, which is what a ClientHello is.
const TLS_HANDSHAKE: u8 = 0x16;

/// What a test proxy saw: the first byte the client sent through the tunnel,
/// and for SOCKS5 the credentials it offered.
#[derive(Default)]
struct Seen {
    first_byte: Option<u8>,
    socks_auth: Option<(String, String)>,
}

/// Record the first byte from the client, then pipe both ways until either
/// side closes.
async fn tunnel(mut client: TcpStream, target: &str, seen: &Mutex<Seen>) {
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        return;
    };
    let mut first = [0u8; 1];
    if client.read_exact(&mut first).await.is_err() {
        return;
    }
    seen.lock().unwrap().first_byte = Some(first[0]);
    if upstream.write_all(&first).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

/// A CONNECT proxy that accepts any target.
async fn spawn_connect_proxy() -> (String, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Seen::default()));
    let state = seen.clone();

    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                // Read the request head a byte at a time, so nothing past it
                // (the start of the tunnel) is consumed here.
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut b = [0u8; 1];
                    if client.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    head.push(b[0]);
                }
                let head = String::from_utf8_lossy(&head);
                let Some(target) = head
                    .strip_prefix("CONNECT ")
                    .and_then(|rest| rest.split_whitespace().next())
                else {
                    return;
                };
                let target = target.to_string();
                if client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                tunnel(client, &target, &state).await;
            });
        }
    });

    (url, seen)
}

/// A SOCKS5 proxy (RFC 1928). Takes no-auth, or username/password
/// (RFC 1929) when the client offers it, and records the credentials.
async fn spawn_socks5_proxy() -> (u16, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let state = seen.clone();

    tokio::spawn(async move {
        while let Ok((mut c, _)) = listener.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                let result: std::io::Result<()> = async {
                    // Greeting: VER NMETHODS METHODS...
                    let mut hdr = [0u8; 2];
                    c.read_exact(&mut hdr).await?;
                    let mut methods = vec![0u8; hdr[1] as usize];
                    c.read_exact(&mut methods).await?;
                    if methods.contains(&0x02) {
                        c.write_all(&[0x05, 0x02]).await?;
                        // VER ULEN UNAME PLEN PASSWD
                        let mut ver_ulen = [0u8; 2];
                        c.read_exact(&mut ver_ulen).await?;
                        let mut user = vec![0u8; ver_ulen[1] as usize];
                        c.read_exact(&mut user).await?;
                        let mut plen = [0u8; 1];
                        c.read_exact(&mut plen).await?;
                        let mut pass = vec![0u8; plen[0] as usize];
                        c.read_exact(&mut pass).await?;
                        state.lock().unwrap().socks_auth = Some((
                            String::from_utf8_lossy(&user).into_owned(),
                            String::from_utf8_lossy(&pass).into_owned(),
                        ));
                        c.write_all(&[0x01, 0x00]).await?;
                    } else {
                        c.write_all(&[0x05, 0x00]).await?;
                    }
                    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
                    let mut req = [0u8; 4];
                    c.read_exact(&mut req).await?;
                    let host = match req[3] {
                        0x01 => {
                            let mut ip = [0u8; 4];
                            c.read_exact(&mut ip).await?;
                            std::net::Ipv4Addr::from(ip).to_string()
                        }
                        0x03 => {
                            let mut len = [0u8; 1];
                            c.read_exact(&mut len).await?;
                            let mut name = vec![0u8; len[0] as usize];
                            c.read_exact(&mut name).await?;
                            String::from_utf8_lossy(&name).into_owned()
                        }
                        _ => return Ok(()),
                    };
                    let mut port = [0u8; 2];
                    c.read_exact(&mut port).await?;
                    let port = u16::from_be_bytes(port);
                    c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    tunnel(c, &format!("{}:{}", host, port), &state).await;
                    Ok(())
                }
                .await;
                let _ = result;
            });
        }
    });

    (port, seen)
}

fn https_config(server: &TlsTestServer, proxy: String) -> RequestConfig {
    let mut config = RequestConfig::new(format!("{}/secret?token=hunter2", server.url()));
    config.proxy = Some(proxy);
    config.verify_certs = Some(false); // self-signed cert
    config.timeout_seconds = Some(5);
    config
}

#[tokio::test]
async fn https_through_a_connect_proxy_is_tls_inside_the_tunnel() {
    let server = TlsTestServer::start(TlsServerConfig::default()).await;
    let (proxy, seen) = spawn_connect_proxy().await;

    let resp = HyperClient::new()
        .send(&https_config(&server, proxy))
        .await
        .expect("request failed");

    assert_eq!(seen.lock().unwrap().first_byte, Some(TLS_HANDSHAKE));
    assert_eq!(resp.status, 200);
    assert!(resp.cert_info.is_some(), "should carry the target's cert");
    server.shutdown().await;
}

#[tokio::test]
async fn https_through_a_socks5_proxy_is_tls_inside_the_tunnel() {
    let server = TlsTestServer::start(TlsServerConfig::default()).await;
    let (port, seen) = spawn_socks5_proxy().await;

    let resp = HyperClient::new()
        .send(&https_config(
            &server,
            format!("socks5://127.0.0.1:{}", port),
        ))
        .await
        .expect("request failed");

    assert_eq!(seen.lock().unwrap().first_byte, Some(TLS_HANDSHAKE));
    assert_eq!(resp.status, 200);
    server.shutdown().await;
}

#[tokio::test]
async fn verify_certs_applies_to_the_target_through_a_connect_proxy() {
    // The test server's cert is self-signed, so with verification on the
    // request has to fail. Before the fix there was no TLS with the target,
    // so there was nothing to verify and the request failed for another
    // reason.
    let server = TlsTestServer::start(TlsServerConfig::default()).await;
    let (proxy, seen) = spawn_connect_proxy().await;
    let mut config = https_config(&server, proxy);
    config.verify_certs = Some(true);

    let result = HyperClient::new().send(&config).await;

    // A handshake with the target did start, so the failure is the cert
    // check and not a broken tunnel.
    assert_eq!(seen.lock().unwrap().first_byte, Some(TLS_HANDSHAKE));
    assert!(
        result.is_err(),
        "self-signed target should fail verification"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn verify_certs_applies_to_the_target_through_a_socks5_proxy() {
    let server = TlsTestServer::start(TlsServerConfig::default()).await;
    let (port, seen) = spawn_socks5_proxy().await;
    let mut config = https_config(&server, format!("socks5://127.0.0.1:{}", port));
    config.verify_certs = Some(true);

    let result = HyperClient::new().send(&config).await;

    // A handshake with the target did start, so the failure is the cert
    // check and not a broken tunnel.
    assert_eq!(seen.lock().unwrap().first_byte, Some(TLS_HANDSHAKE));
    assert!(
        result.is_err(),
        "self-signed target should fail verification"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn socks5_credentials_in_the_proxy_url_are_sent() {
    let server = TlsTestServer::start(TlsServerConfig::default()).await;
    let (port, seen) = spawn_socks5_proxy().await;

    let resp = HyperClient::new()
        .send(&https_config(
            &server,
            format!("socks5://alice:s3cret@127.0.0.1:{}", port),
        ))
        .await
        .expect("request failed");

    assert_eq!(resp.status, 200);
    assert_eq!(
        seen.lock().unwrap().socks_auth,
        Some(("alice".to_string(), "s3cret".to_string()))
    );
    server.shutdown().await;
}

#[tokio::test]
async fn https_proxy_url_is_refused_for_an_https_target() {
    // TLS to the target inside TLS to the proxy isn't supported, and this
    // never worked: the target used to get plaintext. Say so up front.
    let server = TlsTestServer::start(TlsServerConfig::default()).await;
    let (proxy, _) = spawn_connect_proxy().await;
    let proxy = proxy.replacen("http://", "https://", 1);

    let err = HyperClient::new()
        .send(&https_config(&server, proxy))
        .await
        .expect_err("https:// proxy should be refused");

    assert!(
        err.to_string().contains("https:// proxies"),
        "error should say why: {}",
        err
    );
    server.shutdown().await;
}
