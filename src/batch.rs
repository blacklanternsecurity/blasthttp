use std::sync::Arc;

use crate::client::{HttpClient, ClientError};
use crate::config::RequestConfig;
use crate::response::Response;

pub struct BatchResult {
    pub url: String,
    pub result: Result<Response, ClientError>,
}

pub async fn send_batch<C: HttpClient + Send + Sync + 'static>(
    client: Arc<C>,
    configs: Vec<RequestConfig>,
    concurrency: usize,
) -> Vec<BatchResult> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for config in configs {
        let client = client.clone();
        let permit = semaphore.clone();
        let url = config.url.clone();

        let handle = tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            let result = client.send(&config).await;
            BatchResult { url, result }
        });
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(batch_result) => results.push(batch_result),
            Err(e) => results.push(BatchResult {
                url: String::from("<unknown>"),
                result: Err(ClientError { message: format!("task panicked: {}", e) }),
            }),
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::mock::MockClient;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn test_batch_returns_all_results() {
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let configs = vec![
            RequestConfig::new("https://a.com".to_string()),
            RequestConfig::new("https://b.com".to_string()),
            RequestConfig::new("https://c.com".to_string()),
        ];

        let results = send_batch(client, configs, 10).await;
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.result.is_ok());
            assert_eq!(r.result.as_ref().unwrap().status, 200);
        }
    }

    #[tokio::test]
    async fn test_batch_preserves_urls() {
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let configs = vec![
            RequestConfig::new("https://first.com".to_string()),
            RequestConfig::new("https://second.com".to_string()),
        ];

        let results = send_batch(client, configs, 10).await;
        let urls: Vec<&str> = results.iter().map(|r| r.url.as_str()).collect();
        assert!(urls.contains(&"https://first.com"));
        assert!(urls.contains(&"https://second.com"));
    }

    #[tokio::test]
    async fn test_batch_empty_input() {
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let results = send_batch(client, Vec::new(), 10).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_batch_with_errors() {
        let client = Arc::new(MockClient::with_error("connection refused".to_string()));
        let configs = vec![
            RequestConfig::new("https://a.com".to_string()),
            RequestConfig::new("https://b.com".to_string()),
        ];

        let results = send_batch(client, configs, 10).await;
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(r.result.is_err());
        }
    }

    #[tokio::test]
    async fn test_batch_runs_concurrently() {
        let client = Arc::new(
            MockClient::new(200, "ok".to_string())
                .with_delay(Duration::from_millis(100))
        );

        let configs: Vec<RequestConfig> = (0..5)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let start = Instant::now();
        let results = send_batch(client.clone(), configs, 5).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 5);
        // 5 requests with 100ms delay each, all concurrent = ~100ms total
        // Sequential would be ~500ms. Allow generous margin.
        assert!(elapsed < Duration::from_millis(300),
            "batch took {:?}, expected < 300ms (concurrent)", elapsed);
        assert_eq!(client.peak_concurrent(), 5);
    }

    #[tokio::test]
    async fn test_batch_respects_concurrency_limit() {
        let client = Arc::new(
            MockClient::new(200, "ok".to_string())
                .with_delay(Duration::from_millis(100))
        );

        let configs: Vec<RequestConfig> = (0..10)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let results = send_batch(client.clone(), configs, 2).await;

        assert_eq!(results.len(), 10);
        // With concurrency=2, peak should never exceed 2
        assert!(client.peak_concurrent() <= 2,
            "peak concurrent was {}, expected <= 2", client.peak_concurrent());
    }

    #[tokio::test]
    async fn test_batch_concurrency_one_is_sequential() {
        let client = Arc::new(
            MockClient::new(200, "ok".to_string())
                .with_delay(Duration::from_millis(50))
        );

        let configs: Vec<RequestConfig> = (0..4)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let start = Instant::now();
        let results = send_batch(client.clone(), configs, 1).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 4);
        assert_eq!(client.peak_concurrent(), 1);
        // 4 requests * 50ms each, sequential = ~200ms minimum
        assert!(elapsed >= Duration::from_millis(180),
            "batch took {:?}, expected >= 180ms (sequential)", elapsed);
    }
}
