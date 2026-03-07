use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestConfig {
    pub url: String,
    pub timeout_seconds: Option<u64>,
    pub max_body_size: Option<usize>,
    pub follow_redirects: Option<bool>,
    pub max_redirects: Option<u32>,
    pub verify_certs: Option<bool>,
    #[serde(default)]
    pub verbosity: u8,
}

impl RequestConfig {
    pub fn new(url: String) -> Self {
        RequestConfig {
            url,
            timeout_seconds: None,
            max_body_size: None,
            follow_redirects: None,
            max_redirects: None,
            verify_certs: None,
            verbosity: 0,
        }
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
}
