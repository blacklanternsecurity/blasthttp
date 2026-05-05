//! Long-lived handle to a TCP or TLS stream with no HTTP framing applied.
//!
//! Use this when the caller needs to put arbitrary bytes on the wire that
//! a normal HTTP library would refuse to construct — deliberately malformed
//! framing, multiple pipelined requests on one socket, and so on. The
//! connection does not parse, decode, normalize, or validate anything:
//! bytes go out as sent, bytes come back as received.

use super::ClientError;
use super::hyper::{IoReadWrite, connect_stream};
use crate::config::RequestConfig;
use crate::debug::new_debug_log;
use crate::response::CertInfo;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

pub struct RawConnection {
    stream: Arc<Mutex<Option<Box<dyn IoReadWrite + Send + Unpin>>>>,
    cert_info: Option<CertInfo>,
    negotiated_alpn: Option<String>,
    peer_ip: Option<IpAddr>,
}

impl RawConnection {
    /// Open a connection to the target URL. TCP for `http://`, TLS for
    /// `https://`. TLS settings (verify_certs, cipher_string,
    /// min_tls_version, max_tls_version, resolve_ip) come from the
    /// provided RequestConfig. The URL's path and query are ignored at
    /// connect time — only the scheme, host, and port matter.
    pub async fn connect(uri_str: &str, config: &RequestConfig) -> Result<Self, ClientError> {
        let uri: http::Uri = uri_str.parse().map_err(|e: http::uri::InvalidUri| {
            ClientError::invalid_url(format!("invalid URL '{}': {}", uri_str, e))
        })?;
        let log = new_debug_log();
        let (stream, cert_info, negotiated_alpn, peer_ip) =
            connect_stream(&uri, config, &log).await?;
        Ok(Self {
            stream: Arc::new(Mutex::new(Some(stream))),
            cert_info,
            negotiated_alpn,
            peer_ip,
        })
    }

    /// Write bytes to the connection. Bytes go out unmodified — no framing,
    /// no validation, no normalization. The stream is flushed before return.
    pub async fn send_bytes(&self, data: &[u8]) -> Result<(), ClientError> {
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ClientError::connection("connection is closed".to_string()))?;
        stream
            .write_all(data)
            .await
            .map_err(|e| ClientError::connection(format!("write failed: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| ClientError::connection(format!("flush failed: {}", e)))?;
        Ok(())
    }

    /// Read up to `max_bytes` from the connection, returning whatever was
    /// available within `timeout_ms`. A non-empty return means bytes
    /// arrived. An empty return means either the timeout elapsed with no
    /// data or the peer closed the connection cleanly — both signal "no
    /// more data right now". Pass `None` for `timeout_ms` to wait
    /// indefinitely.
    pub async fn read_raw(
        &self,
        max_bytes: usize,
        timeout_ms: Option<u64>,
    ) -> Result<Vec<u8>, ClientError> {
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ClientError::connection("connection is closed".to_string()))?;
        let mut buf = vec![0u8; max_bytes];
        let read_fut = stream.read(&mut buf);
        let n = match timeout_ms {
            Some(ms) => match tokio::time::timeout(Duration::from_millis(ms), read_fut).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    return Err(ClientError::connection(format!("read failed: {}", e)));
                }
                Err(_) => 0,
            },
            None => read_fut
                .await
                .map_err(|e| ClientError::connection(format!("read failed: {}", e)))?,
        };
        buf.truncate(n);
        Ok(buf)
    }

    /// Close the connection. Subsequent send_bytes / read_raw calls error.
    pub async fn close(&self) -> Result<(), ClientError> {
        let mut guard = self.stream.lock().await;
        if let Some(mut stream) = guard.take() {
            let _ = stream.shutdown().await;
        }
        Ok(())
    }

    /// Certificate info captured during the TLS handshake, if any.
    pub fn cert_info(&self) -> Option<CertInfo> {
        self.cert_info.clone()
    }

    /// The ALPN protocol the server selected during the TLS handshake,
    /// if any. None for plain HTTP, or HTTPS connections where the
    /// server didn't advertise ALPN support. Common values: "h2",
    /// "http/1.1".
    pub fn negotiated_alpn(&self) -> Option<String> {
        self.negotiated_alpn.clone()
    }

    /// IP actually used for this connection's TCP socket. `None` if a
    /// proxy was configured (peer_addr would be the proxy, not the
    /// target) or if the OS refused `peer_addr()`.
    pub fn peer_ip(&self) -> Option<String> {
        self.peer_ip.map(|ip| ip.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                if socket.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        });
        (addr, handle)
    }

    fn plain_config() -> RequestConfig {
        RequestConfig::new("http://127.0.0.1/".to_string())
    }

    #[tokio::test]
    async fn roundtrip_send_then_read() {
        let (addr, _srv) = spawn_echo_server().await;
        let url = format!("http://{}", addr);
        let conn = RawConnection::connect(&url, &plain_config()).await.unwrap();

        conn.send_bytes(b"hello blasthttp").await.unwrap();
        let echoed = conn.read_raw(1024, Some(2000)).await.unwrap();
        assert_eq!(echoed, b"hello blasthttp");
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn read_timeout_returns_empty() {
        let (addr, _srv) = spawn_echo_server().await;
        let url = format!("http://{}", addr);
        let conn = RawConnection::connect(&url, &plain_config()).await.unwrap();

        let data = conn.read_raw(1024, Some(100)).await.unwrap();
        assert_eq!(data.len(), 0);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn send_after_close_errors() {
        let (addr, _srv) = spawn_echo_server().await;
        let url = format!("http://{}", addr);
        let conn = RawConnection::connect(&url, &plain_config()).await.unwrap();
        conn.close().await.unwrap();

        let result = conn.send_bytes(b"anything").await;
        assert!(result.is_err(), "send_bytes after close must error");
    }

    #[tokio::test]
    async fn read_after_close_errors() {
        let (addr, _srv) = spawn_echo_server().await;
        let url = format!("http://{}", addr);
        let conn = RawConnection::connect(&url, &plain_config()).await.unwrap();
        conn.close().await.unwrap();

        let result = conn.read_raw(1024, Some(100)).await;
        assert!(result.is_err(), "read_raw after close must error");
    }

    #[tokio::test]
    async fn multiple_sends_and_reads() {
        let (addr, _srv) = spawn_echo_server().await;
        let url = format!("http://{}", addr);
        let conn = RawConnection::connect(&url, &plain_config()).await.unwrap();

        conn.send_bytes(b"hello ").await.unwrap();
        conn.send_bytes(b"world").await.unwrap();

        let mut total = Vec::new();
        while total.len() < 11 {
            let chunk = conn.read_raw(64, Some(1000)).await.unwrap();
            if chunk.is_empty() {
                break;
            }
            total.extend_from_slice(&chunk);
        }
        assert_eq!(total, b"hello world");
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn close_is_idempotent() {
        let (addr, _srv) = spawn_echo_server().await;
        let url = format!("http://{}", addr);
        let conn = RawConnection::connect(&url, &plain_config()).await.unwrap();

        conn.close().await.unwrap();
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn connect_invalid_url_errors() {
        let result = RawConnection::connect("not a url", &plain_config()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn connect_unreachable_errors() {
        // Port 1 is almost certainly not listening.
        let result = RawConnection::connect("http://127.0.0.1:1", &plain_config()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn read_zero_max_bytes_returns_empty() {
        let (addr, _srv) = spawn_echo_server().await;
        let url = format!("http://{}", addr);
        let conn = RawConnection::connect(&url, &plain_config()).await.unwrap();

        let data = conn.read_raw(0, Some(100)).await.unwrap();
        assert_eq!(data.len(), 0);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn peer_close_returns_empty() {
        // Spin up a server that closes immediately after accepting.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket);
        });

        let url = format!("http://{}", addr);
        let conn = RawConnection::connect(&url, &plain_config()).await.unwrap();
        let data = conn.read_raw(1024, Some(1000)).await.unwrap();
        assert_eq!(data.len(), 0, "peer close should return empty, not error");
        conn.close().await.unwrap();
    }
}
