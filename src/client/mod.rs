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
}
