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

#[derive(Debug, Clone)]
pub struct ClientError {
    pub message: String,
    pub kind: ErrorKind,
}

impl ClientError {
    pub fn connection(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Connection,
        }
    }

    pub fn timeout(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Timeout,
        }
    }

    pub fn tls(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Tls,
        }
    }

    pub fn invalid_url(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::InvalidUrl,
        }
    }

    pub fn too_many_redirects(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::TooManyRedirects,
        }
    }

    pub fn status(status: u16, message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Status(status),
        }
    }

    pub fn other(message: String) -> Self {
        ClientError {
            message,
            kind: ErrorKind::Other,
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
