use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestConfig {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<Vec<(String, String)>>,
    pub body: Option<Vec<u8>>,
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
    /// No-op — paths are already sent raw. Kept for API compat with curl --path-as-is.
    pub raw_path: Option<bool>,
    /// Override the HTTP request-line target (like curl --request-target).
    /// Only applies to HTTP/1.1. Bypasses the cached connection pool.
    pub request_target: Option<String>,
    /// Connect TCP to this IP instead of resolving the hostname via DNS
    /// (like curl --resolve). SNI is still set to the original hostname.
    pub resolve_ip: Option<String>,
    /// ALPN protocol list offered during the TLS handshake. When None,
    /// raw connections offer only `http/1.1`. Set to e.g.
    /// `vec!["h2".into()]` to negotiate HTTP/2, or `vec!["h2".into(),
    /// "http/1.1".into()]` to let the server choose. Only meaningful
    /// for HTTPS targets; ignored for plain HTTP.
    pub alpn_protocols: Option<Vec<String>>,
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
            raw_path: None,
            request_target: None,
            resolve_ip: None,
            alpn_protocols: None,
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
