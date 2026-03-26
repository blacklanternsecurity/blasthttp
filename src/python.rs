// Native Python bindings via PyO3.
// Wrapper types ("waitstaff") present Rust internals to Python as native classes.
// Kept separate from Rust structs so the Python API can diverge freely
// (e.g. complex request builders for Phase 4 raw byte control).

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::sync::Arc;

use crate::batch::{self, RateLimiter};
use crate::client::HttpClient;
use crate::client::hyper::HyperClient;
use crate::config::RequestConfig;
use crate::response::{CertInfo, RedirectHop, Response, ResponseHash};

use std::io::Write;

// ── Response wrapper types ────────────────────────────────────────

#[pyclass(name = "ResponseHash")]
struct PyResponseHash {
    inner: ResponseHash,
}

#[pymethods]
impl PyResponseHash {
    #[getter]
    fn body_md5(&self) -> String {
        self.inner.body_md5.clone()
    }
    #[getter]
    fn body_mmh3(&self) -> i32 {
        self.inner.body_mmh3
    }
    #[getter]
    fn body_sha256(&self) -> String {
        self.inner.body_sha256.clone()
    }
    #[getter]
    fn header_md5(&self) -> String {
        self.inner.header_md5.clone()
    }
    #[getter]
    fn header_mmh3(&self) -> i32 {
        self.inner.header_mmh3
    }
    #[getter]
    fn header_sha256(&self) -> String {
        self.inner.header_sha256.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "ResponseHash(body_md5='{}', body_mmh3={})",
            self.inner.body_md5, self.inner.body_mmh3,
        )
    }
}

// ── CertInfo wrapper ──────────────────────────────────────────────

#[pyclass(name = "CertInfo")]
struct PyCertInfo {
    inner: CertInfo,
}

#[pymethods]
impl PyCertInfo {
    #[getter]
    fn common_name(&self) -> Option<String> {
        self.inner.common_name.clone()
    }
    #[getter]
    fn sans(&self) -> Vec<String> {
        self.inner.sans.clone()
    }
    #[getter]
    fn emails(&self) -> Vec<String> {
        self.inner.emails.clone()
    }
    #[getter]
    fn issuer(&self) -> Option<String> {
        self.inner.issuer.clone()
    }
    #[getter]
    fn not_before(&self) -> Option<String> {
        self.inner.not_before.clone()
    }
    #[getter]
    fn not_after(&self) -> Option<String> {
        self.inner.not_after.clone()
    }
    #[getter]
    fn fingerprint_sha256(&self) -> Option<String> {
        self.inner.fingerprint_sha256.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "CertInfo(cn={:?}, sans={:?})",
            self.inner.common_name, self.inner.sans,
        )
    }
}

// ── RedirectHop wrapper ───────────────────────────────────────────

#[pyclass(name = "RedirectHop")]
struct PyRedirectHop {
    inner: RedirectHop,
}

#[pymethods]
impl PyRedirectHop {
    #[getter]
    fn url(&self) -> String {
        self.inner.url.clone()
    }
    #[getter]
    fn status(&self) -> u16 {
        self.inner.status
    }

    fn __repr__(&self) -> String {
        format!(
            "RedirectHop(url='{}', status={})",
            self.inner.url, self.inner.status
        )
    }
}

// ── Response wrapper ──────────────────────────────────────────────

#[pyclass(name = "Response")]
struct PyResponse {
    inner: Response,
}

#[pymethods]
impl PyResponse {
    #[getter]
    fn url(&self) -> String {
        self.inner.url.clone()
    }
    #[getter]
    fn status(&self) -> u16 {
        self.inner.status
    }
    #[getter]
    fn body(&self) -> String {
        self.inner.body.clone()
    }
    #[getter]
    fn elapsed_ms(&self) -> u64 {
        self.inner.elapsed_ms
    }

    /// Raw body as Python bytes (avoids UTF-8 decode for binary responses)
    #[getter]
    fn body_bytes(&self) -> &[u8] {
        &self.inner.body_bytes
    }

    /// Response headers as list of (name, value) tuples.
    /// List, not dict — HTTP allows duplicate header names (e.g. Set-Cookie).
    #[getter]
    fn headers(&self) -> Vec<(String, String)> {
        self.inner.headers.clone()
    }

    /// TLS certificate info (None for plain HTTP)
    #[getter]
    fn cert_info(&self) -> Option<PyCertInfo> {
        self.inner
            .cert_info
            .clone()
            .map(|c| PyCertInfo { inner: c })
    }

    /// Content hashes for fingerprinting
    #[getter]
    fn hash(&self) -> PyResponseHash {
        PyResponseHash {
            inner: self.inner.hash.clone(),
        }
    }

    /// Redirect chain (empty if no redirects followed)
    #[getter]
    fn redirect_chain(&self) -> Vec<PyRedirectHop> {
        self.inner
            .redirect_chain
            .iter()
            .map(|hop| PyRedirectHop { inner: hop.clone() })
            .collect()
    }

    /// Debug messages collected during the request.
    /// Always populated — Python side can log/display as needed.
    #[getter]
    fn debug_log(&self) -> Vec<String> {
        self.inner.debug_log.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "Response(url='{}', status={})",
            self.inner.url, self.inner.status
        )
    }
}

// ── BatchResult wrapper ───────────────────────────────────────────

/// Result of a single request within a batch.
/// Always has url. Has response on success, error on failure.
#[pyclass(name = "BatchResult")]
struct PyBatchResult {
    url: String,
    response: Option<Response>,
    error: Option<String>,
}

#[pymethods]
impl PyBatchResult {
    #[getter]
    fn url(&self) -> String {
        self.url.clone()
    }

    /// The response object (None if the request failed)
    #[getter]
    fn response(&self) -> Option<PyResponse> {
        self.response.clone().map(|r| PyResponse { inner: r })
    }

    /// Error message (None if the request succeeded)
    #[getter]
    fn error(&self) -> Option<String> {
        self.error.clone()
    }

    /// True if the request succeeded
    #[getter]
    fn success(&self) -> bool {
        self.response.is_some()
    }

    fn __repr__(&self) -> String {
        if let Some(ref resp) = self.response {
            format!("BatchResult(url='{}', status={})", self.url, resp.status)
        } else {
            format!("BatchResult(url='{}', error={:?})", self.url, self.error)
        }
    }
}

// ── Main client class ─────────────────────────────────────────────

#[pyclass]
struct BlastHTTP {
    client: Arc<HyperClient>,
    runtime: Arc<tokio::runtime::Runtime>,
    rate_limiter: Option<Arc<RateLimiter>>,
}

#[pymethods]
impl BlastHTTP {
    #[new]
    fn new() -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("failed to create runtime: {}", e)))?;

        Ok(BlastHTTP {
            client: Arc::new(HyperClient::new()),
            runtime: Arc::new(runtime),
            rate_limiter: None,
        })
    }

    /// Set a global rate limit (requests per second) for this client.
    /// Applies to both request() and request_batch().
    /// Set to 0 or None to disable.
    #[pyo3(signature = (rate_limit=None))]
    fn set_rate_limit(&mut self, rate_limit: Option<f64>) {
        self.rate_limiter = rate_limit
            .filter(|&r| r > 0.0)
            .map(|r| Arc::new(RateLimiter::new(r)));
    }

    /// Send a single HTTP request. Returns a Response object.
    #[pyo3(signature = (
        url,
        method=None,
        headers=None,
        body=None,
        timeout=None,
        follow_redirects=None,
        max_redirects=None,
        verify_certs=None,
        proxy=None,
        cipher_string=None,
        min_tls_version=None,
        max_tls_version=None,
        retries=None,
        retry_wait_min_ms=None,
        retry_wait_max_ms=None,
        max_body_size=None,
        raw_path=None,
        request_target=None,
        resolve_ip=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        py: Python<'_>,
        url: String,
        method: Option<String>,
        headers: Option<Vec<(String, String)>>,
        body: Option<String>,
        timeout: Option<u64>,
        follow_redirects: Option<bool>,
        max_redirects: Option<u32>,
        verify_certs: Option<bool>,
        proxy: Option<String>,
        cipher_string: Option<String>,
        min_tls_version: Option<String>,
        max_tls_version: Option<String>,
        retries: Option<u32>,
        retry_wait_min_ms: Option<u64>,
        retry_wait_max_ms: Option<u64>,
        max_body_size: Option<usize>,
        raw_path: Option<bool>,
        request_target: Option<String>,
        resolve_ip: Option<String>,
    ) -> PyResult<PyResponse> {
        let config = RequestConfig {
            url,
            method,
            headers,
            body,
            timeout_seconds: timeout,
            max_body_size,
            follow_redirects,
            max_redirects,
            verify_certs,
            proxy,
            cipher_string,
            min_tls_version,
            max_tls_version,
            retries,
            retry_wait_min_ms,
            retry_wait_max_ms,
            raw_path,
            request_target,
            resolve_ip,
            verbosity: 0,
        };

        // Release the GIL during block_on so Python threads (e.g. test httpservers)
        // can run while we wait for the Rust async runtime.
        let limiter = self.rate_limiter.clone();
        let client = self.client.clone();
        let response = py.allow_threads(|| {
            self.runtime
                .block_on(async move {
                    if let Some(ref limiter) = limiter {
                        limiter.acquire().await;
                    }
                    client.send(&config).await
                })
                .map_err(|e| PyRuntimeError::new_err(e.message))
        })?;

        Ok(PyResponse { inner: response })
    }

    /// Send a batch of requests concurrently. Returns list of BatchResult objects.
    /// Each result has .url, .response (or None), and .error (or None).
    /// rate_limit: max requests per second (None = unlimited).
    /// If set_rate_limit() was called on this client, that takes precedence.
    #[pyo3(signature = (configs, concurrency=50, rate_limit=None))]
    fn request_batch(
        &self,
        py: Python<'_>,
        configs: Vec<PyBatchConfig>,
        concurrency: usize,
        rate_limit: Option<f64>,
    ) -> PyResult<Vec<PyBatchResult>> {
        let request_configs: Vec<RequestConfig> = configs
            .into_iter()
            .map(|c| c.into_request_config())
            .collect();

        let shared_limiter = self.rate_limiter.clone();
        let results = py.allow_threads(|| {
            self.runtime.block_on(batch::send_batch(
                self.client.clone(),
                request_configs,
                concurrency,
                rate_limit,
                shared_limiter,
            ))
        });

        Ok(results
            .into_iter()
            .map(|r| {
                let (response, error) = match r.result {
                    Ok(resp) => (Some(resp), None),
                    Err(e) => (None, Some(e.message)),
                };
                PyBatchResult {
                    url: r.url,
                    response,
                    error,
                }
            })
            .collect())
    }

    /// Download a URL directly to a local file.
    /// Returns the file path on success.
    /// max_size: maximum bytes to download (None = no limit, uses default 10MB)
    #[pyo3(signature = (
        url,
        path,
        max_size=None,
        timeout=None,
        verify_certs=None,
        proxy=None,
        headers=None,
        retries=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn download(
        &self,
        py: Python<'_>,
        url: String,
        path: String,
        max_size: Option<usize>,
        timeout: Option<u64>,
        verify_certs: Option<bool>,
        proxy: Option<String>,
        headers: Option<Vec<(String, String)>>,
        retries: Option<u32>,
    ) -> PyResult<String> {
        let config = RequestConfig {
            url,
            method: Some("GET".to_string()),
            headers,
            body: None,
            timeout_seconds: timeout,
            max_body_size: max_size,
            follow_redirects: Some(true),
            max_redirects: Some(10),
            verify_certs,
            proxy,
            cipher_string: None,
            min_tls_version: None,
            max_tls_version: None,
            retries,
            retry_wait_min_ms: None,
            retry_wait_max_ms: None,
            raw_path: None,
            request_target: None,
            resolve_ip: None,
            verbosity: 0,
        };

        let limiter = self.rate_limiter.clone();
        let client = self.client.clone();
        let response = py.allow_threads(|| {
            self.runtime
                .block_on(async move {
                    if let Some(ref limiter) = limiter {
                        limiter.acquire().await;
                    }
                    client.send(&config).await
                })
                .map_err(|e| PyRuntimeError::new_err(e.message))
        })?;

        // Write body bytes to file
        let mut file = std::fs::File::create(&path).map_err(|e| {
            PyRuntimeError::new_err(format!("failed to create file '{}': {}", path, e))
        })?;
        file.write_all(&response.body_bytes).map_err(|e| {
            PyRuntimeError::new_err(format!("failed to write to '{}': {}", path, e))
        })?;

        Ok(path)
    }
}

// ── Batch config input type ───────────────────────────────────────

/// Per-request config for batch operations.
/// Mirrors send() parameters but as a class for batch input.
#[pyclass(name = "BatchConfig")]
#[derive(Clone)]
struct PyBatchConfig {
    #[pyo3(get, set)]
    url: String,
    #[pyo3(get, set)]
    method: Option<String>,
    #[pyo3(get, set)]
    headers: Option<Vec<(String, String)>>,
    #[pyo3(get, set)]
    body: Option<String>,
    #[pyo3(get, set)]
    timeout: Option<u64>,
    #[pyo3(get, set)]
    follow_redirects: Option<bool>,
    #[pyo3(get, set)]
    max_redirects: Option<u32>,
    #[pyo3(get, set)]
    verify_certs: Option<bool>,
    #[pyo3(get, set)]
    proxy: Option<String>,
    #[pyo3(get, set)]
    cipher_string: Option<String>,
    #[pyo3(get, set)]
    min_tls_version: Option<String>,
    #[pyo3(get, set)]
    max_tls_version: Option<String>,
    #[pyo3(get, set)]
    retries: Option<u32>,
    #[pyo3(get, set)]
    retry_wait_min_ms: Option<u64>,
    #[pyo3(get, set)]
    retry_wait_max_ms: Option<u64>,
    #[pyo3(get, set)]
    raw_path: Option<bool>,
    #[pyo3(get, set)]
    request_target: Option<String>,
    #[pyo3(get, set)]
    resolve_ip: Option<String>,
}

#[pymethods]
impl PyBatchConfig {
    #[new]
    #[pyo3(signature = (
        url,
        method=None,
        headers=None,
        body=None,
        timeout=None,
        follow_redirects=None,
        max_redirects=None,
        verify_certs=None,
        proxy=None,
        cipher_string=None,
        min_tls_version=None,
        max_tls_version=None,
        retries=None,
        retry_wait_min_ms=None,
        retry_wait_max_ms=None,
        raw_path=None,
        request_target=None,
        resolve_ip=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        url: String,
        method: Option<String>,
        headers: Option<Vec<(String, String)>>,
        body: Option<String>,
        timeout: Option<u64>,
        follow_redirects: Option<bool>,
        max_redirects: Option<u32>,
        verify_certs: Option<bool>,
        proxy: Option<String>,
        cipher_string: Option<String>,
        min_tls_version: Option<String>,
        max_tls_version: Option<String>,
        retries: Option<u32>,
        retry_wait_min_ms: Option<u64>,
        retry_wait_max_ms: Option<u64>,
        raw_path: Option<bool>,
        request_target: Option<String>,
        resolve_ip: Option<String>,
    ) -> Self {
        PyBatchConfig {
            url,
            method,
            headers,
            body,
            timeout,
            follow_redirects,
            max_redirects,
            verify_certs,
            proxy,
            cipher_string,
            min_tls_version,
            max_tls_version,
            retries,
            retry_wait_min_ms,
            retry_wait_max_ms,
            raw_path,
            request_target,
            resolve_ip,
        }
    }
}

impl PyBatchConfig {
    fn into_request_config(self) -> RequestConfig {
        RequestConfig {
            url: self.url,
            method: self.method,
            headers: self.headers,
            body: self.body,
            timeout_seconds: self.timeout,
            max_body_size: None,
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            verify_certs: self.verify_certs,
            proxy: self.proxy,
            cipher_string: self.cipher_string,
            min_tls_version: self.min_tls_version,
            max_tls_version: self.max_tls_version,
            retries: self.retries,
            retry_wait_min_ms: self.retry_wait_min_ms,
            retry_wait_max_ms: self.retry_wait_max_ms,
            raw_path: self.raw_path,
            request_target: self.request_target,
            resolve_ip: self.resolve_ip,
            verbosity: 0,
        }
    }
}

// ── Module registration ───────────────────────────────────────────

#[pymodule]
fn blasthttp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<BlastHTTP>()?;
    m.add_class::<PyBatchConfig>()?;
    // Response types are returned by methods, but register them
    // so Python can reference them for type hints / isinstance checks
    m.add_class::<PyResponse>()?;
    m.add_class::<PyBatchResult>()?;
    m.add_class::<PyCertInfo>()?;
    m.add_class::<PyResponseHash>()?;
    m.add_class::<PyRedirectHop>()?;
    Ok(())
}
