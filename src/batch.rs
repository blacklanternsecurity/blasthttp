use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::stream::{self, Stream, StreamExt};

use crate::client::{ClientError, HttpClient};
use crate::config::RequestConfig;
use crate::response::Response;

pub struct BatchResult {
    pub url: String,
    pub result: Result<Response, ClientError>,
}

// ── Rate limiter ──────────────────────────────────────────────────

/// Async rate limiter backed by a single atomic cursor.
///
/// `next_ns` records a monotonic-clock offset (in nanoseconds since
/// construction) at which the NEXT permit becomes available.
/// `acquire` atomically bumps the cursor by one interval and treats
/// the OLD value as its dispatch slot — running immediately if that
/// slot is already past, sleeping until the slot otherwise.
///
/// A CAS loop clamps the base to `max(next_ns, now_ns)` so that a
/// long idle period does not accumulate back-dated slots: a burst
/// arriving after quiet time starts fresh at `now`, not at whatever
/// ancient cursor value the limiter was last left at.
///
/// The previous implementation held a `tokio::sync::Mutex` across a
/// `sleep_until`, which had two compounding failures at high RPS
/// (issue #15):
///   1. Tokio's timer-wheel resolution (~1ms) floored any sub-ms
///      `sleep_until`, so a configured 100k RPS interval (10µs)
///      actually paced dispatch at ~1k QPS.
///   2. The mutex-across-await serialized every worker single-file
///      through the limiter, preventing any parallel progress.
///
/// Atomics with the sleep OUTSIDE any critical section avoid both —
/// workers race on one CAS and then sleep independently.
pub struct RateLimiter {
    interval_ns: u64,
    start: tokio::time::Instant,
    next_ns: AtomicU64,
}

impl RateLimiter {
    pub fn new(requests_per_second: f64) -> Self {
        assert!(
            requests_per_second > 0.0,
            "RateLimiter requires requests_per_second > 0, got {}",
            requests_per_second,
        );
        // Clamp to ≥1ns so the cursor always makes positive progress,
        // even at absurd rates. u64 ns gives ~584y of runtime headroom.
        let interval_ns = (1_000_000_000.0 / requests_per_second).round().max(1.0) as u64;
        RateLimiter {
            interval_ns,
            start: tokio::time::Instant::now(),
            next_ns: AtomicU64::new(0),
        }
    }

    pub fn interval(&self) -> Duration {
        Duration::from_nanos(self.interval_ns)
    }

    pub async fn acquire(&self) {
        // CAS-bump the cursor. `base` is max(current_cursor, now_ns)
        // so an idle limiter resets to "now" rather than letting a
        // stockpile of back-dated slots leak out as a burst.
        // compare_exchange_weak is the right idiom here — cheaper
        // than the strong variant, and spurious failures just re-
        // enter the loop.
        let slot_ns = loop {
            let current = self.next_ns.load(Ordering::Relaxed);
            let now_ns = self.start.elapsed().as_nanos() as u64;
            let base = current.max(now_ns);
            let next = base.saturating_add(self.interval_ns);
            if self
                .next_ns
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break base;
            }
        };
        // Re-read `now_ns` after the CAS resolved — if we lost a few
        // rounds, our slot may already be in the past and no sleep
        // is needed.
        let now_ns = self.start.elapsed().as_nanos() as u64;
        if slot_ns <= now_ns {
            return;
        }
        let deficit_ns = slot_ns - now_ns;
        // Tokio's default timer has ~1ms granularity: a sleep of
        // 10µs actually returns in ~1ms, which would floor throughput
        // at ~1k QPS on tight sequential loops. Skip sub-millisecond
        // sleeps — the cursor has already advanced, so subsequent
        // acquires accumulate the "debt" and eventually cross the
        // 1ms threshold where a real sleep kicks in. Aggregate rate
        // is still capped correctly (e.g. at 100k RPS, one 1ms sleep
        // lands every 100 acquires).
        const SUB_MS_SKIP_THRESHOLD_NS: u64 = 1_000_000;
        if deficit_ns >= SUB_MS_SKIP_THRESHOLD_NS {
            tokio::time::sleep(Duration::from_nanos(deficit_ns)).await;
        }
    }
}

// ── Batch dispatch ────────────────────────────────────────────────

/// Pick the effective rate limiter for a batch call.
///
/// When both a client-level and per-call rate limit are set, use the more
/// restrictive (lower RPS) of the two. This lets modules enforce a tighter
/// rate than the global without overriding the global for other callers.
fn merge_limiters(
    shared: Option<Arc<RateLimiter>>,
    per_call: Option<f64>,
) -> Option<Arc<RateLimiter>> {
    match (shared, per_call) {
        (Some(shared), Some(per_call_rps)) => {
            let shared_interval = shared.interval();
            let per_call_interval = Duration::from_secs_f64(1.0 / per_call_rps);
            if per_call_interval > shared_interval {
                Some(Arc::new(RateLimiter::new(per_call_rps)))
            } else {
                Some(shared)
            }
        }
        (Some(shared), None) => Some(shared),
        (None, Some(rps)) => Some(Arc::new(RateLimiter::new(rps))),
        (None, None) => None,
    }
}

pub async fn send_batch<C: HttpClient + Send + Sync + 'static>(
    client: Arc<C>,
    configs: Vec<RequestConfig>,
    concurrency: usize,
    rate_limit: Option<f64>,
    shared_limiter: Option<Arc<RateLimiter>>,
) -> Vec<BatchResult> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let limiter = merge_limiters(shared_limiter, rate_limit);
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

/// Streaming variant of `send_batch`. Yields `BatchResult`s in completion
/// order (out-of-dispatch-order) as each request finishes, so a slow request
/// doesn't block faster peers that follow it in the input list.
///
/// Architecture: a driver task spawns one tokio task per request and pipes
/// completed `BatchResult`s into an unbounded mpsc channel; the returned
/// stream is the receiver end. Each request runs as its own spawned task so
/// HTTP work keeps progressing while the consumer (e.g. Python) is busy
/// iterating a returned batch — the same in-flight model as `send_batch`.
///
/// `buffer_unordered` is intentionally avoided: its inner futures only make
/// progress while the stream is being polled. While Python iterates a
/// 1000-item batch, no one polls the stream, so 100 in-flight HTTP futures
/// would stall — measured at ~3.7× throughput regression. blastdns gets
/// away with `buffer_unordered` because its actual work runs on persistent
/// worker tasks queued via crossfire; the stream just multiplexes oneshot
/// waits. blasthttp has no such workers, so we spawn per request.
///
/// Spawning has to happen on the runtime, but `send_batch_stream` is called
/// from a synchronous PyO3 constructor that isn't itself on a tokio task.
/// `stream::once(async { ... }).flatten()` defers the driver-spawn into the
/// stream's first poll, which happens inside `PyBatchResultIterator`'s
/// `__anext__` (a `future_into_py` block running on the tokio runtime).
///
/// Concurrency is gated *before* spawn by a semaphore acquire on the driver,
/// so at most `concurrency` requests are in-flight at any time. Rate-limit
/// acquire happens before the semaphore so dispatch pacing matches
/// `send_batch`. In-flight tasks are NOT cancelled if the consumer drops
/// the stream — they run to completion and their sends fail silently. This
/// also matches `send_batch`.
pub fn send_batch_stream<C: HttpClient + Send + Sync + 'static>(
    client: Arc<C>,
    configs: Vec<RequestConfig>,
    concurrency: usize,
    rate_limit: Option<f64>,
    shared_limiter: Option<Arc<RateLimiter>>,
) -> impl Stream<Item = BatchResult> + Send + 'static {
    let limiter = merge_limiters(shared_limiter, rate_limit);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));

    stream::once(async move {
        let (tx, rx) = futures::channel::mpsc::unbounded::<BatchResult>();

        tokio::spawn(async move {
            for config in configs {
                if let Some(ref l) = limiter {
                    l.acquire().await;
                }
                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let client = client.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let url = config.url.clone();
                    let result = client.send(&config).await;
                    let _ = tx.unbounded_send(BatchResult { url, result });
                });
            }
            // Driver's `tx` clone drops here. Channel closes once every
            // per-request task's `tx` clone also drops (i.e. all sends
            // done), signaling stream end to the consumer.
        });

        rx
    })
    .flatten()
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
        let client =
            Arc::new(MockClient::new(200, "ok".to_string()).with_delay(Duration::from_millis(100)));

        let configs: Vec<RequestConfig> = (0..5)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let start = Instant::now();
        let results = send_batch(client.clone(), configs, 5, None, None).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 5);
        assert!(
            elapsed < Duration::from_millis(300),
            "batch took {:?}, expected < 300ms (concurrent)",
            elapsed
        );
        assert_eq!(client.peak_concurrent(), 5);
    }

    #[tokio::test]
    async fn test_batch_respects_concurrency_limit() {
        let client =
            Arc::new(MockClient::new(200, "ok".to_string()).with_delay(Duration::from_millis(100)));

        let configs: Vec<RequestConfig> = (0..10)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let results = send_batch(client.clone(), configs, 2, None, None).await;

        assert_eq!(results.len(), 10);
        assert!(
            client.peak_concurrent() <= 2,
            "peak concurrent was {}, expected <= 2",
            client.peak_concurrent()
        );
    }

    #[tokio::test]
    async fn test_batch_concurrency_one_is_sequential() {
        let client =
            Arc::new(MockClient::new(200, "ok".to_string()).with_delay(Duration::from_millis(50)));

        let configs: Vec<RequestConfig> = (0..4)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let start = Instant::now();
        let results = send_batch(client.clone(), configs, 1, None, None).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 4);
        assert_eq!(client.peak_concurrent(), 1);
        assert!(
            elapsed >= Duration::from_millis(180),
            "batch took {:?}, expected >= 180ms (sequential)",
            elapsed
        );
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
        assert!(
            elapsed < Duration::from_millis(100),
            "unlimited batch took {:?}, expected < 100ms",
            elapsed
        );
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
        assert!(
            elapsed >= Duration::from_millis(350),
            "rate-limited batch took {:?}, expected >= 350ms",
            elapsed
        );
        // But shouldn't be wildly over either
        assert!(
            elapsed < Duration::from_millis(700),
            "rate-limited batch took {:?}, expected < 700ms",
            elapsed
        );
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
        assert!(
            elapsed >= Duration::from_millis(1800),
            "1/sec batch took {:?}, expected >= 1800ms",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_rate_limit_with_concurrency() {
        // Rate limit AND concurrency together
        // 20 req/s = 50ms intervals, concurrency=2, 4 requests with 100ms delay each
        let client =
            Arc::new(MockClient::new(200, "ok".to_string()).with_delay(Duration::from_millis(100)));

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
    async fn test_shared_limiter_applies_when_no_per_call() {
        // shared_limiter at 10 rps should apply when per-call is None
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
        assert!(
            elapsed >= Duration::from_millis(350),
            "shared-limited batch took {:?}, expected >= 350ms",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_per_call_wins_when_more_restrictive() {
        // shared = 100 rps (10ms intervals), per-call = 10 rps (100ms intervals)
        // Per-call is more restrictive, should be used
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let configs: Vec<RequestConfig> = (0..5)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let shared = Arc::new(RateLimiter::new(100.0));
        let start = Instant::now();
        let results = send_batch(client, configs, 50, Some(10.0), Some(shared)).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 5);
        // Per-call 10 rps should win: 4 intervals × 100ms = ~400ms
        assert!(
            elapsed >= Duration::from_millis(350),
            "batch took {:?}, expected >= 350ms (per-call 10 rps should win)",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_shared_wins_when_more_restrictive() {
        // shared = 10 rps (100ms intervals), per-call = 100 rps (10ms intervals)
        // Shared is more restrictive, should be used
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let configs: Vec<RequestConfig> = (0..5)
            .map(|i| RequestConfig::new(format!("https://{}.com", i)))
            .collect();

        let shared = Arc::new(RateLimiter::new(10.0));
        let start = Instant::now();
        let results = send_batch(client, configs, 50, Some(100.0), Some(shared)).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 5);
        // Shared 10 rps should win: 4 intervals × 100ms = ~400ms
        assert!(
            elapsed >= Duration::from_millis(350),
            "batch took {:?}, expected >= 350ms (shared 10 rps should win)",
            elapsed
        );
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
        assert!(
            elapsed >= Duration::from_millis(800),
            "concurrent batches took {:?}, expected >= 800ms",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(1300),
            "concurrent batches took {:?}, expected < 1300ms",
            elapsed
        );
    }

    // ── Issue #15 regression tests ───────────────────────────────
    //
    // When `rate_limit` is set well ABOVE realistic throughput (as a
    // "safety ceiling"), the limiter must impose near-zero overhead
    // over the unlimited path. The mutex-plus-sleep implementation
    // that preceded these tests collapsed to ~1 QPS per millisecond-
    // timer-tick (~1k QPS ceiling) because it held a tokio::sync::
    // Mutex across sleep_until — serializing every worker single-
    // file through the limiter at timer-granularity pace.

    #[tokio::test]
    async fn test_rate_limiter_high_rps_does_not_collapse_to_timer_tick() {
        // Direct unit-level test on RateLimiter. At 100k RPS the
        // configured interval is 10µs; the limiter must not round
        // this up to the ~1ms timer tick and serialize every
        // acquire at that rate.
        let limiter = RateLimiter::new(100_000.0);
        let n = 1000;
        let start = Instant::now();
        for _ in 0..n {
            limiter.acquire().await;
        }
        let elapsed = start.elapsed();
        eprintln!("[bench] 1000 acquires @ 100k RPS: {:?}", elapsed);
        assert!(
            elapsed < Duration::from_millis(250),
            "1000 acquires at 100k RPS took {:?}, expected < 250ms \
             (broken impl collapses to ~1k QPS regardless of \
             configured rate — see issue #15)",
            elapsed,
        );
    }

    #[tokio::test]
    async fn test_send_batch_high_rate_limit_matches_unlimited() {
        // End-to-end: mirror the issue's scenario. Same workload run
        // twice — unlimited, then with rate_limit=100k — should take
        // roughly the same time, modulo scheduler noise.
        let client = Arc::new(MockClient::new(200, "ok".to_string()));
        let n = 1000;
        let make_configs = || -> Vec<RequestConfig> {
            (0..n)
                .map(|i| RequestConfig::new(format!("https://{}.com", i)))
                .collect()
        };

        // Warm-up so the first timing isn't dominated by one-time
        // allocations / cache-warming.
        let _ = send_batch(client.clone(), make_configs(), 100, None, None).await;

        let start = Instant::now();
        let unlimited = send_batch(client.clone(), make_configs(), 100, None, None).await;
        let unlimited_elapsed = start.elapsed();

        let start = Instant::now();
        let limited = send_batch(client.clone(), make_configs(), 100, Some(100_000.0), None).await;
        let limited_elapsed = start.elapsed();

        assert_eq!(unlimited.len(), n);
        assert_eq!(limited.len(), n);

        // Additive 200ms tolerance — absorbs scheduler noise while
        // still catching the 50×+ regression on the broken impl
        // (~1s for 1000 requests vs tens of ms unlimited).
        let overhead = limited_elapsed.saturating_sub(unlimited_elapsed);
        eprintln!(
            "[bench] 1000-req batch: unlimited={:?}, limited@100k={:?}, overhead={:?}",
            unlimited_elapsed, limited_elapsed, overhead,
        );
        assert!(
            overhead < Duration::from_millis(200),
            "rate-limited (100k RPS cap) took {:?}; unlimited took \
             {:?}; overhead {:?} exceeds 200ms tolerance — see \
             issue #15",
            limited_elapsed,
            unlimited_elapsed,
            overhead,
        );
    }
}
