use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestConfig {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<Vec<(String, String)>>,
    pub body: Option<String>,
    pub timeout_seconds: Option<u64>,
    pub max_body_size: Option<usize>,
    pub follow_redirects: Option<bool>,
    pub max_redirects: Option<u32>,
    pub verify_certs: Option<bool>,
    pub proxy: Option<String>,
    pub cipher_string: Option<String>,
    pub min_tls_version: Option<String>,
    pub max_tls_version: Option<String>,
    /// Number of retries on retryable errors (default: 1)
    pub retries: Option<u32>,
    /// Minimum backoff between retries in milliseconds (default: 1000)
    pub retry_wait_min_ms: Option<u64>,
    /// Maximum backoff between retries in milliseconds (default: 30000)
    pub retry_wait_max_ms: Option<u64>,
    #[serde(default)]
    pub verbosity: u8,
}

impl RequestConfig {
    pub fn new(url: String) -> Self {
        RequestConfig {
            url,
            method: None,
            headers: None,
            body: None,
            timeout_seconds: None,
            max_body_size: None,
            follow_redirects: None,
            max_redirects: None,
            verify_certs: None,
            proxy: None,
            cipher_string: None,
            min_tls_version: None,
            max_tls_version: None,
            retries: None,
            retry_wait_min_ms: None,
            retry_wait_max_ms: None,
            verbosity: 0,
        }
    }

    pub fn method(&self) -> &str {
        self.method.as_deref().unwrap_or("GET")
    }

    pub fn timeout(&self) -> u64 {
        self.timeout_seconds.unwrap_or(10)
    }

    pub fn max_body(&self) -> usize {
        self.max_body_size.unwrap_or(10 * 1024 * 1024)
    }

    pub fn should_follow_redirects(&self) -> bool {
        self.follow_redirects.unwrap_or(false)
    }

    pub fn redirect_limit(&self) -> u32 {
        self.max_redirects.unwrap_or(10)
    }

    pub fn should_verify_certs(&self) -> bool {
        self.verify_certs.unwrap_or(false)
    }

    pub fn max_retries(&self) -> u32 {
        self.retries.unwrap_or(1)
    }

    pub fn retry_wait_min(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.retry_wait_min_ms.unwrap_or(1000))
    }

    pub fn retry_wait_max(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.retry_wait_max_ms.unwrap_or(30000))
    }
}
