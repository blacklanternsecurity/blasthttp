use crate::config::RequestConfig;
use crate::response::Response;

pub trait HttpClient {
    fn send(
        &self,
        config: &RequestConfig,
    ) -> impl std::future::Future<Output = Result<Response, ClientError>> + Send;
}

/// What kind of error occurred — used by retry logic to decide
/// whether another attempt is worth it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// Connection refused, reset, DNS failure — retryable
    Connection,
    /// Request timed out — NOT retryable (already waited the full duration)
    Timeout,
    /// TLS handshake failure, cert error — NOT retryable
    Tls,
    /// Malformed URL — NOT retryable
    InvalidUrl,
    /// Too many redirects — NOT retryable
    TooManyRedirects,
    /// Got an HTTP response but status indicates server error — retryable for 429, 500-599 (except 501)
    Status(u16),
    /// Anything else — NOT retryable by default
    Other,
}

impl ErrorKind {
    pub fn is_retryable(&self) -> bool {
        match self {
            ErrorKind::Connection => true,
            // 429 = rate limited, retry makes sense
            ErrorKind::Status(429) => true,
            // 5xx: don't retry at the transport level — let the caller decide.
            // This matches httpx behavior and avoids double-retries when
            // Python-level retry logic (e.g. API key cycling) is in play.
            _ => false,
        }
    }
}

/// Why a TLS handshake failed, in enough detail to decide what to do about it.
///
/// The distinction that matters is whether a *broader* offer would plausibly
/// help. A peer that shares no cipher with us might accept an older one; a peer
/// whose certificate we rejected will reject it again just as hard, and
/// retrying with weaker crypto there would be both futile and alarming.
///
/// Derived from OpenSSL's reason codes rather than its message text. The text
/// is stable enough to log and far too loose to branch on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsFailure {
    /// No cipher suite in common. The clearest signal that a wider offer is
    /// worth trying.
    NoSharedCipher,
    /// No protocol version in common, or the peer rejected the one we picked.
    UnsupportedProtocol,
    /// The peer sent a fatal alert. `description` is OpenSSL's reason text.
    /// handshake_failure most often means the same thing as NoSharedCipher,
    /// but the peer declined to say which, so it is kept separate.
    Alert {
        description: String,
    },
    /// Certificate verification failed. Never a reason to widen the offer.
    CertificateVerify {
        detail: String,
    },
    /// The connection died mid-handshake with no alert. Typical of old servers
    /// and middleboxes choking on a large or unfamiliar ClientHello, and also
    /// of something actively refusing us, which is why it is not on its own
    /// treated as a cipher problem.
    Reset,
    /// The handshake did not complete in time.
    Timeout,
    Other {
        detail: String,
    },
}

impl TlsFailure {
    /// Would offering more ciphers and older protocol versions plausibly help?
    ///
    /// `Alert` is in here, and that is the case that matters in practice. A
    /// server with no cipher in common with us does not send a neatly labelled
    /// "no shared cipher"; that reason code is what OpenSSL raises when *we*
    /// work it out locally. What actually comes back from the wire is a fatal
    /// handshake_failure alert with no explanation. Measured against an
    /// RC4-only server offered AES: the error is
    /// `ssl/tls alert handshake failure`, not `no shared cipher`. Excluding
    /// alerts here would mean never widening the offer in the single most
    /// common case.
    ///
    /// Still conservative about the rest. A certificate rejection, a timeout
    /// and a reset all say nothing about our cipher list, and widening in
    /// response would send deprecated crypto to a peer that never asked for
    /// it.
    pub fn suggests_wider_offer(&self) -> bool {
        matches!(
            self,
            TlsFailure::NoSharedCipher | TlsFailure::UnsupportedProtocol | TlsFailure::Alert { .. }
        )
    }

    /// Classify an OpenSSL handshake error.
    pub fn from_openssl(err: &openssl::ssl::Error) -> Self {
        // Reason codes from the vendored sslerr.h.
        const NO_SHARED_CIPHER: i32 = 193;
        const NO_PROTOCOLS_AVAILABLE: i32 = 191;
        const UNSUPPORTED_PROTOCOL: i32 = 258;
        const UNSUPPORTED_SSL_VERSION: i32 = 259;
        const WRONG_VERSION_NUMBER: i32 = 267;
        const VERSION_TOO_HIGH: i32 = 166;
        const VERSION_TOO_LOW: i32 = 396;
        const CERTIFICATE_VERIFY_FAILED: i32 = 134;
        const TLSV1_ALERT_PROTOCOL_VERSION: i32 = 1070;
        const TLSV1_ALERT_INSUFFICIENT_SECURITY: i32 = 1071;
        const SSLV3_ALERT_HANDSHAKE_FAILURE: i32 = 1040;
        const SSLV3_ALERT_ILLEGAL_PARAMETER: i32 = 1047;

        // Scan the whole stack for a code we recognise rather than reading
        // only the first. OpenSSL pushes several errors for one failure and
        // the most specific is not reliably at the front: a generic
        // "ssl handshake failure" often sits on top of the reason that
        // actually explains it.
        if let Some(stack) = err.ssl_error() {
            let mut fallback: Option<TlsFailure> = None;

            for e in stack.errors() {
                let reason = e.reason().unwrap_or("").to_string();
                let classified = match e.reason_code() {
                    NO_SHARED_CIPHER => Some(TlsFailure::NoSharedCipher),
                    // The peer telling us our ciphers are too weak is the same
                    // actionable fact as having none in common, from the other
                    // direction.
                    TLSV1_ALERT_INSUFFICIENT_SECURITY => Some(TlsFailure::NoSharedCipher),
                    NO_PROTOCOLS_AVAILABLE
                    | UNSUPPORTED_PROTOCOL
                    | UNSUPPORTED_SSL_VERSION
                    | WRONG_VERSION_NUMBER
                    | VERSION_TOO_HIGH
                    | VERSION_TOO_LOW
                    | TLSV1_ALERT_PROTOCOL_VERSION => Some(TlsFailure::UnsupportedProtocol),
                    CERTIFICATE_VERIFY_FAILED => {
                        Some(TlsFailure::CertificateVerify { detail: reason })
                    }
                    SSLV3_ALERT_HANDSHAKE_FAILURE | SSLV3_ALERT_ILLEGAL_PARAMETER => {
                        Some(TlsFailure::Alert {
                            description: reason,
                        })
                    }
                    _ => {
                        // Unrecognised: keep the first one as a description of
                        // last resort, but carry on looking for a code we know.
                        fallback.get_or_insert(TlsFailure::Other { detail: reason });
                        None
                    }
                };
                if let Some(failure) = classified {
                    return failure;
                }
            }

            if let Some(failure) = fallback {
                return failure;
            }
        }

        // No reason stack: the failure was below TLS. SYSCALL with an io cause
        // is a reset; without one it is an unexpected EOF, which OpenSSL
        // reports the same way.
        match err.io_error() {
            Some(io) if io.kind() == std::io::ErrorKind::TimedOut => TlsFailure::Timeout,
            Some(_) => TlsFailure::Reset,
            None => TlsFailure::Reset,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientError {
    pub message: String,
    pub kind: ErrorKind,
    /// Structured detail when the failure was a TLS handshake, so callers can
    /// branch on why rather than substring-matching `message`.
    pub tls_failure: Option<TlsFailure>,
}

impl ClientError {
    pub fn connection(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Connection,
            tls_failure: None,
        }
    }

    pub fn timeout(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Timeout,
            tls_failure: None,
        }
    }

    pub fn tls(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Tls,
            tls_failure: None,
        }
    }

    pub fn invalid_url(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::InvalidUrl,
            tls_failure: None,
        }
    }

    pub fn too_many_redirects(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::TooManyRedirects,
            tls_failure: None,
        }
    }

    pub fn status(status: u16, message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Status(status),
            tls_failure: None,
        }
    }

    /// A TLS failure that knows why. Prefer this over `tls` wherever an
    /// `openssl::ssl::Error` is in hand, since the reason is what the profile
    /// ladder branches on and it cannot be recovered from the message text.
    pub fn tls_detailed(message: String, failure: TlsFailure) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Tls,
            tls_failure: Some(failure),
        }
    }

    pub fn other(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Other,
            tls_failure: None,
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub mod hyper;
pub mod proxy;
pub mod raw;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
mod tests {
    use super::*;
    use mock::MockClient;

    #[tokio::test]
    async fn test_mock_returns_configured_status() {
        let client = MockClient::new(200, "OK".to_string());
        let config = RequestConfig::new("https://example.com".to_string());
        let response = client.send(&config).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body(), "OK");
    }

    #[tokio::test]
    async fn test_mock_returns_404() {
        let client = MockClient::new(404, "Not Found".to_string());
        let config = RequestConfig::new("https://example.com".to_string());
        let response = client.send(&config).await.unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body(), "Not Found");
    }

    #[tokio::test]
    async fn test_mock_returns_empty_body() {
        let client = MockClient::new(204, String::new());
        let config = RequestConfig::new("https://example.com".to_string());
        let response = client.send(&config).await.unwrap();
        assert_eq!(response.status, 204);
        assert!(response.body().is_empty());
    }

    #[tokio::test]
    async fn test_mock_preserves_url() {
        let client = MockClient::new(200, "hi".to_string());
        let config = RequestConfig::new("https://target.com/path?q=1".to_string());
        let response = client.send(&config).await.unwrap();
        assert_eq!(response.url, "https://target.com/path?q=1");
    }

    #[tokio::test]
    async fn test_mock_error() {
        let client = MockClient::with_error("connection refused".to_string());
        let config = RequestConfig::new("https://example.com".to_string());
        let result = client.send(&config).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().message, "connection refused");
    }

    #[tokio::test]
    async fn test_mock_echoes_method() {
        let client = MockClient::new(200, String::new()).with_echo();
        let mut config = RequestConfig::new("https://example.com".to_string());
        config.method = Some("POST".to_string());
        let response = client.send(&config).await.unwrap();
        assert!(response.body().contains("method=POST"));
    }

    #[tokio::test]
    async fn test_mock_echoes_body() {
        let client = MockClient::new(200, String::new()).with_echo();
        let mut config = RequestConfig::new("https://example.com".to_string());
        config.method = Some("POST".to_string());
        config.body = Some(b"test data".to_vec());
        let response = client.send(&config).await.unwrap();
        assert!(response.body().contains("body=test data"));
    }

    #[tokio::test]
    async fn test_mock_echoes_headers() {
        let client = MockClient::new(200, String::new()).with_echo();
        let mut config = RequestConfig::new("https://example.com".to_string());
        config.headers = Some(vec![
            ("X-Custom".to_string(), "value1".to_string()),
            ("Authorization".to_string(), "Bearer tok".to_string()),
        ]);
        let response = client.send(&config).await.unwrap();
        assert!(response.body().contains("headers=2"));
    }

    #[tokio::test]
    async fn test_mock_returns_headers() {
        let client = MockClient::new(200, "ok".to_string()).with_headers(vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-custom".to_string(), "test".to_string()),
        ]);
        let config = RequestConfig::new("https://example.com".to_string());
        let response = client.send(&config).await.unwrap();
        assert_eq!(response.headers.len(), 2);
        assert_eq!(response.headers[0].0, "content-type");
    }

    #[tokio::test]
    async fn test_config_defaults() {
        let config = RequestConfig::new("https://example.com".to_string());
        assert_eq!(config.method(), "GET");
        assert_eq!(config.timeout(), 10);
        assert_eq!(config.max_body(), 10 * 1024 * 1024);
        assert!(!config.should_follow_redirects());
        assert!(!config.should_verify_certs());
        assert_eq!(config.redirect_limit(), 10);
    }

    #[tokio::test]
    async fn test_config_overrides() {
        let mut config = RequestConfig::new("https://example.com".to_string());
        config.method = Some("PUT".to_string());
        config.timeout_seconds = Some(30);
        config.verify_certs = Some(true);
        config.follow_redirects = Some(true);
        assert_eq!(config.method(), "PUT");
        assert_eq!(config.timeout(), 30);
        assert!(config.should_verify_certs());
        assert!(config.should_follow_redirects());
    }

    // ── ErrorKind tests ──────────────────────────────────────────

    #[test]
    fn test_connection_error_is_retryable() {
        assert!(ErrorKind::Connection.is_retryable());
    }

    #[test]
    fn test_timeout_error_is_not_retryable() {
        assert!(!ErrorKind::Timeout.is_retryable());
    }

    #[test]
    fn test_tls_error_is_not_retryable() {
        assert!(!ErrorKind::Tls.is_retryable());
    }

    #[test]
    fn test_invalid_url_is_not_retryable() {
        assert!(!ErrorKind::InvalidUrl.is_retryable());
    }

    #[test]
    fn test_too_many_redirects_is_not_retryable() {
        assert!(!ErrorKind::TooManyRedirects.is_retryable());
    }

    #[test]
    fn test_status_429_is_retryable() {
        assert!(ErrorKind::Status(429).is_retryable());
    }

    #[test]
    fn test_status_500_is_not_retryable() {
        assert!(!ErrorKind::Status(500).is_retryable());
    }

    #[test]
    fn test_status_502_is_not_retryable() {
        assert!(!ErrorKind::Status(502).is_retryable());
    }

    #[test]
    fn test_status_503_is_not_retryable() {
        assert!(!ErrorKind::Status(503).is_retryable());
    }

    #[test]
    fn test_status_501_is_not_retryable() {
        assert!(!ErrorKind::Status(501).is_retryable());
    }

    #[test]
    fn test_status_404_is_not_retryable() {
        assert!(!ErrorKind::Status(404).is_retryable());
    }

    #[test]
    fn test_status_200_is_not_retryable() {
        assert!(!ErrorKind::Status(200).is_retryable());
    }

    #[test]
    fn test_other_error_is_not_retryable() {
        assert!(!ErrorKind::Other.is_retryable());
    }

    // ── Retry config defaults ────────────────────────────────────

    #[test]
    fn test_retry_defaults() {
        let config = RequestConfig::new("https://example.com".to_string());
        assert_eq!(config.max_retries(), 1);
        assert_eq!(config.retry_wait_min(), std::time::Duration::from_secs(1));
        assert_eq!(config.retry_wait_max(), std::time::Duration::from_secs(30));
    }

    #[test]
    fn test_retry_config_overrides() {
        let mut config = RequestConfig::new("https://example.com".to_string());
        config.retries = Some(3);
        config.retry_wait_min_ms = Some(500);
        config.retry_wait_max_ms = Some(5000);
        assert_eq!(config.max_retries(), 3);
        assert_eq!(
            config.retry_wait_min(),
            std::time::Duration::from_millis(500)
        );
        assert_eq!(
            config.retry_wait_max(),
            std::time::Duration::from_millis(5000)
        );
    }

    #[test]
    fn test_zero_retries() {
        let mut config = RequestConfig::new("https://example.com".to_string());
        config.retries = Some(0);
        assert_eq!(config.max_retries(), 0);
    }
}

#[cfg(test)]
mod tls_failure_tests {
    use super::*;

    #[test]
    fn test_negotiation_failures_suggest_a_wider_offer() {
        // The three shapes a "we could not agree" answer arrives in.
        assert!(TlsFailure::NoSharedCipher.suggests_wider_offer());
        assert!(TlsFailure::UnsupportedProtocol.suggests_wider_offer());
        assert!(
            TlsFailure::Alert {
                description: "ssl/tls alert handshake failure".to_string(),
            }
            .suggests_wider_offer(),
            "a handshake_failure alert is what a real cipher mismatch looks \
             like on the wire; excluding it would defeat the ladder in its \
             most common case"
        );
    }

    #[test]
    fn test_other_failures_do_not_suggest_a_wider_offer() {
        // Widening the offer in response to any of these would send weaker
        // crypto to a peer whose objection had nothing to do with our ciphers.
        assert!(
            !TlsFailure::CertificateVerify {
                detail: "self signed certificate".to_string(),
            }
            .suggests_wider_offer()
        );
        assert!(!TlsFailure::Reset.suggests_wider_offer());
        assert!(!TlsFailure::Timeout.suggests_wider_offer());
        assert!(
            !TlsFailure::Other {
                detail: "something else".to_string(),
            }
            .suggests_wider_offer()
        );
    }

    #[test]
    fn test_constructors_leave_tls_failure_unset() {
        // Only the TLS-aware constructor carries detail; everything else must
        // not claim to know why a handshake failed.
        assert!(ClientError::connection("x".into()).tls_failure.is_none());
        assert!(ClientError::timeout("x".into()).tls_failure.is_none());
        assert!(ClientError::tls("x".into()).tls_failure.is_none());

        let detailed = ClientError::tls_detailed("x".into(), TlsFailure::NoSharedCipher);
        assert_eq!(detailed.kind, ErrorKind::Tls);
        assert_eq!(detailed.tls_failure, Some(TlsFailure::NoSharedCipher));
    }
}
