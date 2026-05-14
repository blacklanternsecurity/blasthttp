use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::{ClientError, ErrorKind, HttpClient};
use crate::config::RequestConfig;
use crate::response::Response;

pub struct MockClient {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
    error: Option<String>,
    delay: Option<Duration>,
    concurrent_count: Arc<AtomicU32>,
    peak_concurrent: Arc<AtomicU32>,
    echo_config: bool,
}

impl MockClient {
    pub fn new(status: u16, body: String) -> Self {
        MockClient {
            status,
            body,
            headers: Vec::new(),
            error: None,
            delay: None,
            concurrent_count: Arc::new(AtomicU32::new(0)),
            peak_concurrent: Arc::new(AtomicU32::new(0)),
            echo_config: false,
        }
    }

    pub fn with_error(message: String) -> Self {
        MockClient {
            status: 0,
            body: String::new(),
            headers: Vec::new(),
            error: Some(message),
            delay: None,
            concurrent_count: Arc::new(AtomicU32::new(0)),
            peak_concurrent: Arc::new(AtomicU32::new(0)),
            echo_config: false,
        }
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_echo(mut self) -> Self {
        self.echo_config = true;
        self
    }

    pub fn peak_concurrent(&self) -> u32 {
        self.peak_concurrent.load(Ordering::SeqCst)
    }
}

/// Mock that returns a specific ErrorKind (for testing retry classification)
pub struct ErrorKindMockClient {
    pub kind: ErrorKind,
    pub message: String,
}

impl HttpClient for ErrorKindMockClient {
    async fn send(&self, _config: &RequestConfig) -> Result<Response, ClientError> {
        Err(ClientError {
            message: self.message.clone(),
            kind: self.kind.clone(),
        })
    }
}

/// Mock that returns different results on each call.
/// Used to test retry logic: fail N times then succeed.
pub struct SequenceMockClient {
    /// Sequence of results. Each call pops from front.
    /// When exhausted, returns the last result repeatedly.
    call_count: AtomicU32,
    /// Number of initial calls that return an error
    fail_count: u32,
    /// Error kind to return for failed calls
    fail_kind: ErrorKind,
    /// Status code to return on success
    success_status: u16,
}

impl SequenceMockClient {
    /// Create a mock that fails `fail_count` times with `fail_kind`, then succeeds with `success_status`.
    pub fn new(fail_count: u32, fail_kind: ErrorKind, success_status: u16) -> Self {
        SequenceMockClient {
            call_count: AtomicU32::new(0),
            fail_count,
            fail_kind,
            success_status,
        }
    }

    pub fn total_calls(&self) -> u32 {
        self.call_count.load(Ordering::SeqCst)
    }
}

impl HttpClient for SequenceMockClient {
    async fn send(&self, config: &RequestConfig) -> Result<Response, ClientError> {
        let call = self.call_count.fetch_add(1, Ordering::SeqCst);

        if call < self.fail_count {
            return Err(ClientError {
                message: format!("mock error on call {}", call),
                kind: self.fail_kind.clone(),
            });
        }

        let body_bytes = b"ok".to_vec();
        Ok(Response {
            url: config.url.clone(),
            status: self.success_status,
            headers: Vec::new(),
            body_bytes,
            elapsed_ms: 0,
            redirect_chain: Vec::new(),
            cert_info: None,
            peer_ip: None,
            request_url: config.url.clone(),
            request_method: config.method().to_string(),
            debug_log: Vec::new(),
            body_cache: std::sync::OnceLock::new(),
            raw_headers_cache: std::sync::OnceLock::new(),
            cookies_cache: std::sync::OnceLock::new(),
            hash_cache: std::sync::OnceLock::new(),
        })
    }
}

impl HttpClient for MockClient {
    async fn send(&self, config: &RequestConfig) -> Result<Response, ClientError> {
        if let Some(ref msg) = self.error {
            return Err(ClientError::connection(msg.clone()));
        }

        let current = self.concurrent_count.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_concurrent.fetch_max(current, Ordering::SeqCst);

        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }

        self.concurrent_count.fetch_sub(1, Ordering::SeqCst);

        let body_bytes = if self.echo_config {
            let body_str = config
                .body
                .as_deref()
                .map(String::from_utf8_lossy)
                .unwrap_or_default();
            format!(
                "method={} body={} headers={}",
                config.method(),
                body_str,
                config.headers.as_ref().map(|h| h.len()).unwrap_or(0),
            )
            .into_bytes()
        } else {
            self.body.clone().into_bytes()
        };
        Ok(Response {
            url: config.url.clone(),
            status: self.status,
            headers: self.headers.clone(),
            body_bytes,
            elapsed_ms: 0,
            redirect_chain: Vec::new(),
            cert_info: None,
            peer_ip: None,
            request_url: config.url.clone(),
            request_method: config.method().to_string(),
            debug_log: Vec::new(),
            body_cache: std::sync::OnceLock::new(),
            raw_headers_cache: std::sync::OnceLock::new(),
            cookies_cache: std::sync::OnceLock::new(),
            hash_cache: std::sync::OnceLock::new(),
        })
    }
}
