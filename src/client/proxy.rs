//! Proxy handling for connect_stream.
//!
//! Supports two proxy modes:
//!
//! - HTTP proxy: client opens TCP to the proxy, sends `CONNECT host:port HTTP/1.1`,
//!   parses the response, and on 200 OK treats the socket as a raw tunnel to
//!   the target. Used only for TLS targets since plain-HTTP through an HTTP
//!   forward-proxy is rejected upstream (see badhttp's api.scan_url check).
//!
//! - SOCKS5 proxy: client opens TCP to the proxy, does a SOCKS5 method
//!   negotiation (no-auth or username/password), issues a CONNECT command
//!   with the target's hostname, reads the reply, and on success treats the
//!   socket as a raw tunnel. Works for any target.

use super::ClientError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub(crate) enum ProxyScheme {
    Http,
    Socks5,
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyConfig {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Parse a proxy URL like `http://host:port`, `socks5://host:port`, or
/// `socks5://user:pass@host:port`. Ports default to 8080 for HTTP and
/// 1080 for SOCKS5.
pub(crate) fn parse_proxy_url(proxy_url: &str) -> Result<ProxyConfig, ClientError> {
    let (scheme_str, rest) = proxy_url.split_once("://").ok_or_else(|| {
        ClientError::other(format!("invalid proxy URL (missing '://'): {}", proxy_url))
    })?;
    let scheme = match scheme_str.to_ascii_lowercase().as_str() {
        "http" => ProxyScheme::Http,
        "socks5" | "socks5h" => ProxyScheme::Socks5,
        other => {
            return Err(ClientError::other(format!(
                "unsupported proxy scheme '{}'; use http:// or socks5://",
                other
            )));
        }
    };

    // Split off userinfo (if any) and trailing path (discard).
    let (userinfo, hostport_rest) = match rest.split_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let hostport = hostport_rest.split('/').next().unwrap_or(hostport_rest);

    let (username, password) = match userinfo {
        Some(u) => match u.split_once(':') {
            Some((user, pass)) => (Some(user.to_string()), Some(pass.to_string())),
            None => (Some(u.to_string()), None),
        },
        None => (None, None),
    };

    // Split host:port from the right so that IPv6 literals could be supported later.
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|_| {
                ClientError::other(format!("invalid proxy port '{}' in {}", p, proxy_url))
            })?;
            (h.to_string(), port)
        }
        None => {
            let default_port = match scheme {
                ProxyScheme::Http => 8080,
                ProxyScheme::Socks5 => 1080,
            };
            (hostport.to_string(), default_port)
        }
    };

    if host.is_empty() {
        return Err(ClientError::other(format!(
            "invalid proxy URL (empty host): {}",
            proxy_url
        )));
    }

    Ok(ProxyConfig {
        scheme,
        host,
        port,
        username,
        password,
    })
}

/// Send an HTTP CONNECT request over an already-opened TCP socket to establish
/// a byte-transparent tunnel to `target_host:target_port`. Returns the same
/// socket on 200 OK; returns an error (connection-class) on any other status
/// or malformed response.
pub(crate) async fn perform_http_connect(
    tcp: &mut TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<(), ClientError> {
    let req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         \r\n",
        host = target_host,
        port = target_port,
    );
    tcp.write_all(req.as_bytes())
        .await
        .map_err(|e| ClientError::connection(format!("proxy CONNECT write failed: {}", e)))?;

    let mut buf = vec![0u8; 8192];
    let mut total = 0;
    loop {
        if total >= buf.len() {
            return Err(ClientError::connection(
                "proxy CONNECT response exceeded 8KB".into(),
            ));
        }
        let n = tcp
            .read(&mut buf[total..])
            .await
            .map_err(|e| ClientError::connection(format!("proxy CONNECT read failed: {}", e)))?;
        if n == 0 {
            return Err(ClientError::connection(
                "proxy closed connection during CONNECT".into(),
            ));
        }
        total += n;
        if find_crlf_crlf(&buf[..total]).is_some() {
            break;
        }
    }

    let response = &buf[..total];
    let status_line_end = response
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(response.len());
    let status_line = &response[..status_line_end];
    let parts: Vec<&[u8]> = status_line.splitn(3, |&b| b == b' ').collect();
    if parts.len() < 2 {
        return Err(ClientError::connection(format!(
            "proxy returned malformed CONNECT response: {:?}",
            String::from_utf8_lossy(status_line)
        )));
    }
    let status_code: u16 = std::str::from_utf8(parts[1])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            ClientError::connection(format!(
                "proxy returned unparseable status code: {:?}",
                String::from_utf8_lossy(parts[1])
            ))
        })?;

    if status_code != 200 {
        return Err(ClientError::connection(format!(
            "proxy rejected CONNECT to {}:{} with status: {}",
            target_host,
            target_port,
            String::from_utf8_lossy(status_line)
        )));
    }

    Ok(())
}

/// Perform a SOCKS5 handshake + CONNECT on an already-opened TCP socket,
/// opening a byte-transparent tunnel to `target_host:target_port`.
pub(crate) async fn perform_socks5(
    tcp: &mut TcpStream,
    target_host: &str,
    target_port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), ClientError> {
    let has_creds = username.is_some() && password.is_some();

    // Method negotiation.
    let offered = if has_creds {
        vec![0x00u8, 0x02u8]
    } else {
        vec![0x00u8]
    };
    let mut greeting = Vec::with_capacity(2 + offered.len());
    greeting.push(0x05u8);
    greeting.push(offered.len() as u8);
    greeting.extend_from_slice(&offered);
    tcp.write_all(&greeting)
        .await
        .map_err(|e| ClientError::connection(format!("SOCKS5 greeting write failed: {}", e)))?;

    let mut chosen = [0u8; 2];
    tcp.read_exact(&mut chosen)
        .await
        .map_err(|e| ClientError::connection(format!("SOCKS5 greeting read failed: {}", e)))?;
    if chosen[0] != 0x05 {
        return Err(ClientError::connection(format!(
            "SOCKS5 invalid version in greeting reply: 0x{:02x}",
            chosen[0]
        )));
    }
    match chosen[1] {
        0x00 => {}
        0x02 => {
            let u = username.ok_or_else(|| {
                ClientError::connection(
                    "SOCKS5 proxy required username/password but none provided".into(),
                )
            })?;
            let p = password.ok_or_else(|| {
                ClientError::connection(
                    "SOCKS5 proxy required username/password but none provided".into(),
                )
            })?;
            if u.len() > 255 || p.len() > 255 {
                return Err(ClientError::connection(
                    "SOCKS5 username/password must be <=255 bytes each".into(),
                ));
            }
            let mut auth = Vec::with_capacity(3 + u.len() + p.len());
            auth.push(0x01u8);
            auth.push(u.len() as u8);
            auth.extend_from_slice(u.as_bytes());
            auth.push(p.len() as u8);
            auth.extend_from_slice(p.as_bytes());
            tcp.write_all(&auth)
                .await
                .map_err(|e| ClientError::connection(format!("SOCKS5 auth write failed: {}", e)))?;
            let mut auth_reply = [0u8; 2];
            tcp.read_exact(&mut auth_reply)
                .await
                .map_err(|e| ClientError::connection(format!("SOCKS5 auth read failed: {}", e)))?;
            if auth_reply[1] != 0x00 {
                return Err(ClientError::connection(format!(
                    "SOCKS5 username/password auth rejected (status 0x{:02x})",
                    auth_reply[1]
                )));
            }
        }
        0xff => {
            return Err(ClientError::connection(
                "SOCKS5 proxy rejected all offered authentication methods".into(),
            ));
        }
        other => {
            return Err(ClientError::connection(format!(
                "SOCKS5 proxy selected unexpected auth method: 0x{:02x}",
                other
            )));
        }
    }

    // CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = vec![0x05u8, 0x01u8, 0x00u8];
    if let Ok(ipv4) = target_host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = target_host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ipv6.octets());
    } else {
        if target_host.len() > 255 {
            return Err(ClientError::connection(
                "SOCKS5 target hostname must be <=255 bytes".into(),
            ));
        }
        req.push(0x03);
        req.push(target_host.len() as u8);
        req.extend_from_slice(target_host.as_bytes());
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    tcp.write_all(&req)
        .await
        .map_err(|e| ClientError::connection(format!("SOCKS5 connect write failed: {}", e)))?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr)
        .await
        .map_err(|e| ClientError::connection(format!("SOCKS5 connect read failed: {}", e)))?;
    if hdr[0] != 0x05 {
        return Err(ClientError::connection(format!(
            "SOCKS5 invalid version in connect reply: 0x{:02x}",
            hdr[0]
        )));
    }
    if hdr[1] != 0x00 {
        return Err(ClientError::connection(format!(
            "SOCKS5 CONNECT to {}:{} failed: {}",
            target_host,
            target_port,
            socks5_error_text(hdr[1])
        )));
    }

    // Drain bound address + port so the socket position is at the start of tunneled data.
    let atyp = hdr[3];
    let addr_len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len_byte = [0u8; 1];
            tcp.read_exact(&mut len_byte)
                .await
                .map_err(|e| ClientError::connection(format!("SOCKS5 reply read failed: {}", e)))?;
            len_byte[0] as usize
        }
        other => {
            return Err(ClientError::connection(format!(
                "SOCKS5 reply had unexpected ATYP: 0x{:02x}",
                other
            )));
        }
    };
    let mut tail = vec![0u8; addr_len + 2];
    tcp.read_exact(&mut tail)
        .await
        .map_err(|e| ClientError::connection(format!("SOCKS5 reply drain failed: {}", e)))?;

    Ok(())
}

fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn socks5_error_text(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown SOCKS5 error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parse_http_proxy_basic() {
        let p = parse_proxy_url("http://proxy:8080").unwrap();
        assert!(matches!(p.scheme, ProxyScheme::Http));
        assert_eq!(p.host, "proxy");
        assert_eq!(p.port, 8080);
        assert!(p.username.is_none());
        assert!(p.password.is_none());
    }

    #[test]
    fn parse_socks5_with_credentials() {
        let p = parse_proxy_url("socks5://alice:s3cret@proxy:1080").unwrap();
        assert!(matches!(p.scheme, ProxyScheme::Socks5));
        assert_eq!(p.host, "proxy");
        assert_eq!(p.port, 1080);
        assert_eq!(p.username.as_deref(), Some("alice"));
        assert_eq!(p.password.as_deref(), Some("s3cret"));
    }

    #[test]
    fn parse_default_ports() {
        assert_eq!(parse_proxy_url("http://p").unwrap().port, 8080);
        assert_eq!(parse_proxy_url("socks5://p").unwrap().port, 1080);
    }

    #[test]
    fn parse_socks5h_is_socks5() {
        let p = parse_proxy_url("socks5h://p:1080").unwrap();
        assert!(matches!(p.scheme, ProxyScheme::Socks5));
    }

    #[test]
    fn parse_rejects_bad_scheme() {
        assert!(parse_proxy_url("ftp://p:21").is_err());
        assert!(parse_proxy_url("no-scheme-here").is_err());
        assert!(parse_proxy_url("").is_err());
    }

    #[test]
    fn parse_rejects_empty_host() {
        assert!(parse_proxy_url("http://:8080").is_err());
    }

    #[test]
    fn parse_rejects_bad_port() {
        assert!(parse_proxy_url("http://p:notanumber").is_err());
    }

    #[tokio::test]
    async fn http_connect_success_returns_ok() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    return;
                }
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        perform_http_connect(&mut tcp, "example.com", 443)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn http_connect_rejected_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    return;
                }
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
        });
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let err = perform_http_connect(&mut tcp, "example.com", 80)
            .await
            .unwrap_err();
        assert!(err.message.contains("403"), "err was: {}", err.message);
    }

    #[tokio::test]
    async fn socks5_no_auth_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // greeting: VER=5, NMETHODS=1, methods=[00]
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, &[0x05u8, 0x01, 0x00]);
            // reply: method=no-auth
            sock.write_all(&[0x05u8, 0x00]).await.unwrap();
            // connect request hdr
            let mut hdr = [0u8; 4];
            sock.read_exact(&mut hdr).await.unwrap();
            assert_eq!(&hdr[..3], &[0x05u8, 0x01, 0x00]);
            assert_eq!(hdr[3], 0x03); // domain
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.unwrap();
            let mut addr_buf = vec![0u8; len[0] as usize + 2];
            sock.read_exact(&mut addr_buf).await.unwrap();
            // success reply
            sock.write_all(&[0x05u8, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        perform_socks5(&mut tcp, "target.example", 443, None, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn socks5_refused_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            sock.write_all(&[0x05u8, 0x00]).await.unwrap();
            let mut hdr = [0u8; 4];
            sock.read_exact(&mut hdr).await.unwrap();
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.unwrap();
            let mut addr_buf = vec![0u8; len[0] as usize + 2];
            sock.read_exact(&mut addr_buf).await.unwrap();
            // refused reply (REP=0x05)
            sock.write_all(&[0x05u8, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let err = perform_socks5(&mut tcp, "target.example", 443, None, None)
            .await
            .unwrap_err();
        assert!(err.message.contains("refused"), "err was: {}", err.message);
    }

    #[tokio::test]
    async fn socks5_all_methods_rejected_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            // reply: 0xff = no acceptable methods
            sock.write_all(&[0x05u8, 0xff]).await.unwrap();
        });
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let err = perform_socks5(&mut tcp, "target.example", 443, None, None)
            .await
            .unwrap_err();
        assert!(
            err.message.contains("all offered"),
            "err was: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn socks5_userpass_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // expect greeting with two methods offered
            let mut greeting = [0u8; 4];
            sock.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 0x05);
            assert_eq!(greeting[1], 0x02);
            assert_eq!(&greeting[2..], &[0x00, 0x02]);
            // select userpass auth
            sock.write_all(&[0x05u8, 0x02]).await.unwrap();
            // read auth: VER=1 ULEN user PLEN pass
            let mut auth_hdr = [0u8; 2];
            sock.read_exact(&mut auth_hdr).await.unwrap();
            assert_eq!(auth_hdr[0], 0x01);
            let ulen = auth_hdr[1] as usize;
            let mut user = vec![0u8; ulen];
            sock.read_exact(&mut user).await.unwrap();
            assert_eq!(&user, b"alice");
            let mut plen_b = [0u8; 1];
            sock.read_exact(&mut plen_b).await.unwrap();
            let mut pass = vec![0u8; plen_b[0] as usize];
            sock.read_exact(&mut pass).await.unwrap();
            assert_eq!(&pass, b"s3cret");
            // accept auth
            sock.write_all(&[0x01u8, 0x00]).await.unwrap();
            // connect request + success reply
            let mut hdr = [0u8; 4];
            sock.read_exact(&mut hdr).await.unwrap();
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.unwrap();
            let mut addr_buf = vec![0u8; len[0] as usize + 2];
            sock.read_exact(&mut addr_buf).await.unwrap();
            sock.write_all(&[0x05u8, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        perform_socks5(
            &mut tcp,
            "target.example",
            443,
            Some("alice"),
            Some("s3cret"),
        )
        .await
        .unwrap();
    }
}
