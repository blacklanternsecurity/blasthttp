use crate::config::RequestConfig;
use crate::response::Response;

pub trait HttpClient {
    fn send(&self, config: &RequestConfig) -> impl std::future::Future<Output = Result<Response, ClientError>> + Send;
}

#[derive(Debug)]
pub struct ClientError {
    pub message: String,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub mod hyper;

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
        assert_eq!(response.body, "OK");
    }

    #[tokio::test]
    async fn test_mock_returns_404() {
        let client = MockClient::new(404, "Not Found".to_string());
        let config = RequestConfig::new("https://example.com".to_string());
        let response = client.send(&config).await.unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body, "Not Found");
    }

    #[tokio::test]
    async fn test_mock_returns_empty_body() {
        let client = MockClient::new(204, String::new());
        let config = RequestConfig::new("https://example.com".to_string());
        let response = client.send(&config).await.unwrap();
        assert_eq!(response.status, 204);
        assert!(response.body.is_empty());
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
        assert!(response.body.contains("method=POST"));
    }

    #[tokio::test]
    async fn test_mock_echoes_body() {
        let client = MockClient::new(200, String::new()).with_echo();
        let mut config = RequestConfig::new("https://example.com".to_string());
        config.method = Some("POST".to_string());
        config.body = Some("test data".to_string());
        let response = client.send(&config).await.unwrap();
        assert!(response.body.contains("body=test data"));
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
        assert!(response.body.contains("headers=2"));
    }

    #[tokio::test]
    async fn test_mock_returns_headers() {
        let client = MockClient::new(200, "ok".to_string())
            .with_headers(vec![
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
}
