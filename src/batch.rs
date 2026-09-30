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

// ── Host discovery scheduler ──────────────────────────────────────

/// Stops a burst of requests to one host from each separately working out
/// which connection profile that host wants.
///
/// The problem. The client remembers, per host, the profile that got through,
/// so a scan pays for the ladder once rather than once per request. At the
/// start of a batch that has not been paid yet: if fifty requests to one host
/// go out together, all fifty find the default refused and all fifty shift,
/// a hundred handshakes where fifty one would have done.
///
/// What does not work, and this was built and measured before being thrown
/// away: a per-host lock, so the first request discovers and the rest wait on
/// it. It does cut the handshakes, and it is slower anyway, because a waiter
/// cannot be released until the leader has classified its response,
/// classification needs the body, and so the wait is a whole request long. A
/// protection product does not refuse the handshake; it takes the connection
/// and then answers 403, which puts the one fact worth knowing in the last
/// byte to arrive. Waiting also broke the rule that a slow request never
/// holds up faster ones behind it, which is the entire promise of
/// `send_batch_stream`.
///
/// What works instead is to not wait. A request whose host is already being
/// worked out steps aside and lets a request for a *different* host have its
/// slot, then goes once there is an answer. Nothing idles, so the saving
/// costs no time.
///
/// The condition is the whole design, and it comes straight from the test
/// that killed the lock: six requests, one host, concurrency six. Step aside
/// there and you are standing in the street, because every other request
/// wants the same host. So: **only step aside when there is undispatched work
/// for a different host.** When there is not, go and discover it yourself and
/// accept the duplicate. That makes this strictly better or equal to having
/// no scheduler at all, never worse, which is what the lock failed to be.
struct HostGate {
    /// Someone is making the first request to this host, so an answer is
    /// coming.
    claimed: bool,
    /// Flips once a request to this host finishes. A `watch` rather than a
    /// `Notify` because the answer can land between a waiter reading the
    /// state and awaiting on it, and a watch carries the value so that
    /// waiter sees it instead of sleeping until its timeout.
    answered: tokio::sync::watch::Sender<bool>,
}

struct SchedulerState {
    gates: std::collections::HashMap<String, HostGate>,
    /// Requests not yet dispatched, in total and per host. Together these
    /// answer the only question the scheduler asks: is there work for a
    /// different host that could use the slot I would otherwise sit in?
    remaining_total: usize,
    remaining_by_host: std::collections::HashMap<String, usize>,
    /// How many requests are standing aside right now, and the ceiling on
    /// that. A request that has stepped aside holds no permit, so it stops
    /// counting against concurrency and the driver spawns another in its
    /// place. Without a ceiling, a batch alternating between two slow hosts
    /// would have the driver spawn task after task, each stepping aside and
    /// freeing the permit for the next, until the whole batch was resident.
    /// The ceiling keeps live tasks inside the envelope the stream already
    /// had.
    aside: usize,
    aside_limit: usize,
}

pub(crate) struct Scheduler {
    state: std::sync::Mutex<SchedulerState>,
}

/// What a request should do about its host.
pub(crate) enum Dispatch {
    /// Go, and you are the one discovering this host. Hold the guard for the
    /// request.
    Lead(LeaderGuard),
    /// Go. Either the host is already answered, or there was nothing else to
    /// do with the slot so discovering it twice is the cheaper mistake.
    Go,
    /// Stand aside until this says true, then ask again.
    Aside(tokio::sync::watch::Receiver<bool>, AsideGuard),
}

/// Held for the duration of the first request to a host. Marks the host
/// answered when dropped, so a request that fails, times out or panics
/// releases whoever stepped aside for it instead of leaving them on the
/// timeout.
pub(crate) struct LeaderGuard {
    sched: Arc<Scheduler>,
    host: String,
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        if let Ok(mut st) = self.sched.state.lock()
            && let Some(gate) = st.gates.get_mut(&self.host)
        {
            // `send` refuses when nothing is subscribed and leaves the value
            // alone, which is the common case here: usually the leader
            // finishes with nobody yet standing aside. The answer would then
            // be lost, and the next request to this host would stand aside
            // waiting for news that had already been and gone.
            gate.answered.send_replace(true);
        }
    }
}

/// Held while a request stands aside, so the ceiling is released however the
/// wait ends.
pub(crate) struct AsideGuard {
    sched: Arc<Scheduler>,
}

impl Drop for AsideGuard {
    fn drop(&mut self) {
        if let Ok(mut st) = self.sched.state.lock() {
            st.aside = st.aside.saturating_sub(1);
        }
    }
}

/// Host and port, matching how the client keys its per-host profile memory.
/// A URL that will not parse gets a bucket under its own text, which just
/// means it coordinates with nothing.
fn host_key(url: &str) -> String {
    let Ok(uri) = url.parse::<http::Uri>() else {
        return url.to_string();
    };
    match uri.host() {
        Some(h) => {
            let default_port = if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            };
            format!("{}:{}", h, uri.port_u16().unwrap_or(default_port))
        }
        None => url.to_string(),
    }
}

impl Scheduler {
    fn new(configs: &[RequestConfig], concurrency: usize) -> Arc<Self> {
        let mut remaining_by_host: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for c in configs {
            *remaining_by_host.entry(host_key(&c.url)).or_insert(0) += 1;
        }
        Arc::new(Scheduler {
            state: std::sync::Mutex::new(SchedulerState {
                gates: std::collections::HashMap::new(),
                remaining_total: configs.len(),
                remaining_by_host,
                aside: 0,
                aside_limit: concurrency.max(1),
            }),
        })
    }

    /// Decide and commit in one lock, because deciding and then committing
    /// separately lets two requests both look, both see no one discovering,
    /// and both go: the duplicate this exists to prevent.
    ///
    /// `may_stand_aside` is false on the second ask, after a wait, so a
    /// request stands aside at most once and cannot be starved by a host
    /// that keeps being re-claimed.
    fn dispatch(self: &Arc<Self>, host: &str, may_stand_aside: bool) -> Dispatch {
        let Ok(mut st) = self.state.lock() else {
            return Dispatch::Go;
        };

        if may_stand_aside && st.aside < st.aside_limit {
            let busy = st
                .gates
                .get(host)
                .is_some_and(|g| g.claimed && !*g.answered.borrow());
            let mine = st.remaining_by_host.get(host).copied().unwrap_or(0);
            let elsewhere = st.remaining_total.saturating_sub(mine) > 0;
            if busy && elsewhere {
                let rx = st.gates[host].answered.subscribe();
                st.aside += 1;
                return Dispatch::Aside(
                    rx,
                    AsideGuard {
                        sched: self.clone(),
                    },
                );
            }
        }

        // Going, so take the slot.
        st.remaining_total = st.remaining_total.saturating_sub(1);
        if let Some(n) = st.remaining_by_host.get_mut(host) {
            *n = n.saturating_sub(1);
        }
        let gate = st
            .gates
            .entry(host.to_string())
            .or_insert_with(|| HostGate {
                claimed: false,
                answered: tokio::sync::watch::Sender::new(false),
            });
        if gate.claimed || *gate.answered.borrow() {
            return Dispatch::Go;
        }
        gate.claimed = true;
        Dispatch::Lead(LeaderGuard {
            sched: self.clone(),
            host: host.to_string(),
        })
    }
}

/// How long a request stands aside before giving up and going anyway.
///
/// Only a backstop. The leader's guard releases waiters the moment its
/// request ends, errors included, so this fires when a leader is wedged in a
/// way its own timeout did not catch. Sized off the request timeout, since a
/// leader cannot legitimately outlive that.
fn step_aside_limit(config: &RequestConfig) -> Duration {
    Duration::from_secs(config.timeout().clamp(1, 60))
}

/// Stand aside if asked to, then report whether this request is the one
/// discovering its host.
///
/// Takes the caller's concurrency permit, if it is already holding one, and
/// gives it back only if it never stood aside. The two callers differ on
/// exactly this: `send_batch` has not taken a permit yet and passes `None`,
/// while the stream driver hands one over with the request and needs it
/// released for the wait, since a request standing aside is not in flight
/// and holding a slot as though it were is the lock all over again.
async fn await_turn(
    sched: &Arc<Scheduler>,
    host: &str,
    config: &RequestConfig,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> (
    Option<LeaderGuard>,
    Option<tokio::sync::OwnedSemaphorePermit>,
) {
    match sched.dispatch(host, true) {
        Dispatch::Lead(g) => (Some(g), permit),
        Dispatch::Go => (None, permit),
        Dispatch::Aside(mut rx, aside) => {
            drop(permit);
            if !*rx.borrow() {
                let _ = tokio::time::timeout(step_aside_limit(config), rx.changed()).await;
            }
            drop(aside);
            let lead = match sched.dispatch(host, false) {
                Dispatch::Lead(g) => Some(g),
                _ => None,
            };
            (lead, None)
        }
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
    let sched = Scheduler::new(&configs, concurrency);
    let mut handles = Vec::new();

    for config in configs {
        // Rate limit: pace dispatch before spawning the task
        if let Some(ref limiter) = limiter {
            limiter.acquire().await;
        }

        let client = client.clone();
        let permit = semaphore.clone();
        let url = config.url.clone();
        let sched = sched.clone();

        let handle = tokio::spawn(async move {
            // Stand aside before taking a permit rather than after, so the
            // slot is genuinely free while we are standing there. Waiting
            // with a permit in hand would be the lock this replaces.
            let host = host_key(&config.url);
            let (_lead, _) = await_turn(&sched, &host, &config, None).await;

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
    let sched = Scheduler::new(&configs, concurrency);

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
                let sched = sched.clone();
                let semaphore = semaphore.clone();
                tokio::spawn(async move {
                    let host = host_key(&config.url);
                    // The driver holds the permit here, unlike `send_batch`,
                    // so standing aside means handing it back. The driver is
                    // parked on the next acquire and takes it immediately,
                    // which is what sends the slot to another host. Dispatch
                    // order is untouched; only this one request is late.
                    let (_lead, permit) = await_turn(&sched, &host, &config, Some(permit)).await;
                    // Re-take a slot only if we gave ours up.
                    let permit = match permit {
                        Some(p) => Some(p),
                        None => semaphore.acquire_owned().await.ok(),
                    };

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

#[cfg(test)]
mod scheduler_tests {
    use super::*;

    fn cfgs(urls: &[&str]) -> Vec<RequestConfig> {
        urls.iter()
            .map(|u| RequestConfig::new(u.to_string()))
            .collect()
    }

    fn is_aside(d: &Dispatch) -> bool {
        matches!(d, Dispatch::Aside(..))
    }

    #[test]
    fn test_one_host_never_stands_aside() {
        // The case that killed the previous attempt, as a unit test. Six
        // requests to one host: standing aside means standing in the street,
        // because there is no other host to hand the slot to. Every one of
        // them has to go, even though that means discovering the host six
        // times over.
        let sched = Scheduler::new(&cfgs(&["https://a.test/"; 6]), 6);
        let host = host_key("https://a.test/");

        let first = sched.dispatch(&host, true);
        assert!(matches!(first, Dispatch::Lead(_)), "first one leads");

        for i in 0..5 {
            let d = sched.dispatch(&host, true);
            assert!(!is_aside(&d), "request {i} should have gone, not waited");
        }
    }

    #[test]
    fn test_another_host_waiting_is_what_makes_it_worth_stepping_aside() {
        // Same shape, one difference: there is work for a different host, so
        // the slot this request would have sat in has somewhere to go.
        let sched = Scheduler::new(
            &cfgs(&["https://a.test/", "https://a.test/", "https://b.test/"]),
            4,
        );
        let a = host_key("https://a.test/");

        // Bound, not matched in place: the guard marks the host answered when
        // it drops, so letting it die at the end of the statement would mean
        // the discovering request had already finished.
        let lead = sched.dispatch(&a, true);
        assert!(matches!(lead, Dispatch::Lead(_)));
        assert!(
            is_aside(&sched.dispatch(&a, true)),
            "b.test is still queued"
        );
    }

    #[test]
    fn test_the_second_ask_always_goes() {
        // After standing aside once a request goes regardless, so a host that
        // keeps being re-claimed cannot starve the requests behind it.
        let sched = Scheduler::new(
            &cfgs(&["https://a.test/", "https://a.test/", "https://b.test/"]),
            4,
        );
        let a = host_key("https://a.test/");

        let _lead = sched.dispatch(&a, true);
        assert!(is_aside(&sched.dispatch(&a, true)));
        assert!(!is_aside(&sched.dispatch(&a, false)), "the second ask goes");
    }

    #[test]
    fn test_an_answered_host_is_not_worth_waiting_for() {
        let configs = cfgs(&["https://a.test/", "https://a.test/", "https://b.test/"]);
        let sched = Scheduler::new(&configs, 4);
        let a = host_key("https://a.test/");

        let lead = sched.dispatch(&a, true);
        assert!(matches!(lead, Dispatch::Lead(_)));
        drop(lead); // the discovering request finished

        assert!(
            !is_aside(&sched.dispatch(&a, true)),
            "there is an answer now, so nothing to wait for"
        );
    }

    #[test]
    fn test_a_leader_that_dies_releases_the_host() {
        // The guard marks the host answered on drop rather than on success,
        // so a request that errors or panics does not leave everyone who
        // stepped aside for it sitting on the timeout.
        let configs = cfgs(&["https://a.test/", "https://a.test/", "https://b.test/"]);
        let sched = Scheduler::new(&configs, 4);
        let a = host_key("https://a.test/");

        let Dispatch::Lead(lead) = sched.dispatch(&a, true) else {
            panic!("expected to lead");
        };
        let Dispatch::Aside(rx, _guard) = sched.dispatch(&a, true) else {
            panic!("expected to stand aside");
        };
        assert!(!*rx.borrow());

        drop(lead);
        assert!(
            *rx.borrow(),
            "dropping the leader should release the waiter"
        );
    }

    #[test]
    fn test_the_ceiling_bounds_how_many_can_be_standing_aside() {
        // Without this, a batch alternating between two slow hosts has the
        // driver spawn a task, watch it hand the permit straight back, spawn
        // another, and so on until the whole batch is resident.
        let mut urls = vec!["https://a.test/"; 10];
        urls.push("https://b.test/");
        let sched = Scheduler::new(&cfgs(&urls), 2);
        let a = host_key("https://a.test/");

        let _lead = sched.dispatch(&a, true);
        let _one = sched.dispatch(&a, true);
        let _two = sched.dispatch(&a, true);
        assert!(
            is_aside(&_one) && is_aside(&_two),
            "both fit under a ceiling of 2"
        );
        assert!(
            !is_aside(&sched.dispatch(&a, true)),
            "the third should go rather than pile up"
        );
    }

    #[test]
    fn test_a_freed_slot_lets_another_stand_aside() {
        let mut urls = vec!["https://a.test/"; 10];
        urls.push("https://b.test/");
        let sched = Scheduler::new(&cfgs(&urls), 1);
        let a = host_key("https://a.test/");

        let _lead = sched.dispatch(&a, true);
        let waiting = sched.dispatch(&a, true);
        assert!(is_aside(&waiting));
        assert!(!is_aside(&sched.dispatch(&a, true)), "ceiling of 1 is full");

        drop(waiting);
        assert!(is_aside(&sched.dispatch(&a, true)), "and free again after");
    }

    #[test]
    fn test_host_key_ignores_the_path_and_fills_in_the_port() {
        assert_eq!(
            host_key("https://a.test/one"),
            host_key("https://a.test/two")
        );
        assert_eq!(host_key("https://a.test/"), "a.test:443");
        assert_eq!(host_key("http://a.test/"), "a.test:80");
        assert_eq!(host_key("https://a.test:8443/"), "a.test:8443");
        assert_ne!(host_key("https://a.test/"), host_key("https://b.test/"));
    }
}
