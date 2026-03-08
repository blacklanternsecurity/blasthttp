use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::config::RequestConfig;
use crate::response::Response;
use super::{HttpClient, ClientError};

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

impl HttpClient for MockClient {
    async fn send(&self, config: &RequestConfig) -> Result<Response, ClientError> {
        if let Some(ref msg) = self.error {
            return Err(ClientError { message: msg.clone() });
        }

        let current = self.concurrent_count.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_concurrent.fetch_max(current, Ordering::SeqCst);

        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }

        self.concurrent_count.fetch_sub(1, Ordering::SeqCst);

        let body = if self.echo_config {
            format!(
                "method={} body={} headers={}",
                config.method(),
                config.body.as_deref().unwrap_or(""),
                config.headers.as_ref().map(|h| h.len()).unwrap_or(0),
            )
        } else {
            self.body.clone()
        };

        Ok(Response {
            url: config.url.clone(),
            status: self.status,
            headers: self.headers.clone(),
            body_bytes: body.as_bytes().to_vec(),
            body,
            elapsed_ms: 0,
            redirect_chain: Vec::new(),
            cert_info: None,
        })
    }
}
