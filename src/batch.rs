use std::sync::Arc;
use std::time::Duration;

use crate::client::{HttpClient, ClientError};
use crate::config::RequestConfig;
use crate::response::Response;

pub struct BatchResult {
    pub url: String,
    pub result: Result<Response, ClientError>,
}

// ── Rate limiter ──────────────────────────────────────────────────

/// Simple async rate limiter using a permit-dispenser pattern.
/// Uses tokio::sync::Mutex because we await (sleep) while holding the lock.
pub struct RateLimiter {
    interval: Duration,
    next: tokio::sync::Mutex<tokio::time::Instant>,
}

impl RateLimiter {
    pub fn new(requests_per_second: f64) -> Self {
        let interval = Duration::from_secs_f64(1.0 / requests_per_second);
        RateLimiter {
            interval,
            next: tokio::sync::Mutex::new(tokio::time::Instant::now()),
        }
    }

    pub async fn acquire(&self) {
        let mut next = self.next.lock().await;
        tokio::time::sleep_until(*next).await;
        *next = tokio::time::Instant::now() + self.interval;
    }
}

// ── Batch dispatch ────────────────────────────────────────────────

pub async fn send_batch<C: HttpClient + Send + Sync + 'static>(
    client: Arc<C>,
    configs: Vec<RequestConfig>,
    concurrency: usize,
    rate_limit: Option<f64>,
    shared_limiter: Option<Arc<RateLimiter>>,
) -> Vec<BatchResult> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    // Client-level limiter takes precedence, then per-call, then unlimited
    let limiter = shared_limiter.or_else(|| rate_limit.map(|rps| Arc::new(RateLimiter::new(rps))));
    let mut handles = Vec::new();

    for config in configs {
        // Rate limit: pace dispatch before spawning the task
        if let Some(ref limiter) = limiter {
            limiter.acquire().await;
        }

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
                result: Err(ClientError::other(format!("task panicked: {}", e))),
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

        let results = send_batch(client, configs, 10, None, None).await;
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

        let results = send_batch(client, configs, 10, None, None).await;
        let urls: Vec<&str> = results.iter().map(|r| r.url.as_str()).collect();
        assert!(urls.contains(&"https://first.com"));
        assert!(urls.contains(&"https://second.com"));
    }

    #[tokio::test]
    async fn test_batch_empty_input() {
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let results = send_batch(client, Vec::new(), 10, None, None).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_batch_with_errors() {
        let client = Arc::new(MockClient::with_error("connection refused".to_string()));
        let configs = vec![
            RequestConfig::new("https://a.com".to_string()),
            RequestConfig::new("https://b.com".to_string()),
        ];

        let results = send_batch(client, configs, 10, None, None).await;
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
        let results = send_batch(client.clone(), configs, 5, None, None).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 5);
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

        let results = send_batch(client.clone(), configs, 2, None, None).await;

        assert_eq!(results.len(), 10);
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
        let results = send_batch(client.clone(), configs, 1, None, None).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 4);
        assert_eq!(client.peak_concurrent(), 1);
        assert!(elapsed >= Duration::from_millis(180),
            "batch took {:?}, expected >= 180ms (sequential)", elapsed);
    }

    // ── Rate limiting tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_rate_limit_none_is_unlimited() {
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let configs: Vec<RequestConfig> = (0..5)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let start = Instant::now();
        let results = send_batch(client, configs, 50, None, None).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 5);
        // No rate limit + no delay = nearly instant
        assert!(elapsed < Duration::from_millis(100),
            "unlimited batch took {:?}, expected < 100ms", elapsed);
    }

    #[tokio::test]
    async fn test_rate_limit_paces_dispatch() {
        // 10 requests/sec = 100ms between each dispatch
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let configs: Vec<RequestConfig> = (0..5)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let start = Instant::now();
        let results = send_batch(client, configs, 50, Some(10.0), None).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 5);
        // 5 requests at 10/sec = 4 intervals × 100ms = ~400ms minimum
        assert!(elapsed >= Duration::from_millis(350),
            "rate-limited batch took {:?}, expected >= 350ms", elapsed);
        // But shouldn't be wildly over either
        assert!(elapsed < Duration::from_millis(700),
            "rate-limited batch took {:?}, expected < 700ms", elapsed);
    }

    #[tokio::test]
    async fn test_rate_limit_one_per_second() {
        // 1 request/sec — very slow, but easy to verify
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let configs: Vec<RequestConfig> = (0..3)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let start = Instant::now();
        let results = send_batch(client, configs, 50, Some(1.0), None).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 3);
        // 3 requests at 1/sec = 2 intervals × 1s = ~2s minimum
        assert!(elapsed >= Duration::from_millis(1800),
            "1/sec batch took {:?}, expected >= 1800ms", elapsed);
    }

    #[tokio::test]
    async fn test_rate_limit_with_concurrency() {
        // Rate limit AND concurrency together
        // 20 req/s = 50ms intervals, concurrency=2, 4 requests with 100ms delay each
        let client = Arc::new(
            MockClient::new(200, "ok".to_string())
                .with_delay(Duration::from_millis(100))
        );

        let configs: Vec<RequestConfig> = (0..4)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let results = send_batch(client.clone(), configs, 2, Some(20.0), None).await;
        assert_eq!(results.len(), 4);
        // All should succeed
        for r in &results {
            assert!(r.result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_shared_limiter_takes_precedence() {
        // shared_limiter at 10 rps should override per-call None
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let configs: Vec<RequestConfig> = (0..5)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let shared = Arc::new(RateLimiter::new(10.0));
        let start = Instant::now();
        let results = send_batch(client, configs, 50, None, Some(shared)).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 5);
        // 5 requests at 10/sec = 4 intervals × 100ms = ~400ms minimum
        assert!(elapsed >= Duration::from_millis(350),
            "shared-limited batch took {:?}, expected >= 350ms", elapsed);
    }

    #[tokio::test]
    async fn test_shared_limiter_across_concurrent_batches() {
        // Two concurrent send_batch calls sharing the same limiter at 10 rps.
        // 10 total requests should take ~900ms (9 intervals × 100ms).
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let shared = Arc::new(RateLimiter::new(10.0));

        let configs1: Vec<RequestConfig> = (0..5)
            .map(|i| RequestConfig::new(format!("https://a{}.com", i)))
            .collect();
        let configs2: Vec<RequestConfig> = (0..5)
            .map(|i| RequestConfig::new(format!("https://b{}.com", i)))
            .collect();

        let c1 = client.clone();
        let s1 = shared.clone();
        let c2 = client.clone();
        let s2 = shared.clone();

        let start = Instant::now();
        let (r1, r2) = tokio::join!(
            send_batch(c1, configs1, 50, None, Some(s1)),
            send_batch(c2, configs2, 50, None, Some(s2)),
        );
        let elapsed = start.elapsed();

        assert_eq!(r1.len() + r2.len(), 10);
        // 10 requests sharing one 10 rps limiter = 9 intervals × 100ms = ~900ms
        assert!(elapsed >= Duration::from_millis(800),
            "concurrent batches took {:?}, expected >= 800ms", elapsed);
        assert!(elapsed < Duration::from_millis(1300),
            "concurrent batches took {:?}, expected < 1300ms", elapsed);
    }
}
