// Native Python bindings via PyO3.
// Wrapper types ("waitstaff") present Rust internals to Python as native classes.
// Kept separate from Rust structs so the Python API can diverge freely
// (e.g. complex request builders for Phase 4 raw byte control).

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3_async_runtimes::tokio::future_into_py;
use std::sync::Arc;

use crate::batch::{self, RateLimiter};
use crate::client::HttpClient;
use crate::client::hyper::HyperClient;
use crate::client::raw;
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
    rate_limiter: Option<Arc<RateLimiter>>,
}

#[pymethods]
impl BlastHTTP {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(BlastHTTP {
            client: Arc::new(HyperClient::new()),
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
    fn request<'py>(
        &self,
        py: Python<'py>,
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
    ) -> PyResult<Bound<'py, PyAny>> {
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
            alpn_protocols: None,
            verbosity: 0,
        };

        let limiter = self.rate_limiter.clone();
        let client = self.client.clone();

        future_into_py(py, async move {
            if let Some(ref limiter) = limiter {
                limiter.acquire().await;
            }
            let response = client
                .send(&config)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.message))?;
            Ok(PyResponse { inner: response })
        })
    }

    /// Send a batch of requests concurrently. Returns list of BatchResult objects.
    /// Each result has .url, .response (or None), and .error (or None).
    /// rate_limit: max requests per second (None = unlimited).
    /// If both set_rate_limit() and rate_limit are set, the more restrictive
    /// (lower RPS) limit is used.
    #[pyo3(signature = (configs, concurrency=50, rate_limit=None))]
    fn request_batch<'py>(
        &self,
        py: Python<'py>,
        configs: Vec<PyBatchConfig>,
        concurrency: usize,
        rate_limit: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request_configs: Vec<RequestConfig> = configs
            .into_iter()
            .map(|c| c.into_request_config())
            .collect();

        let shared_limiter = self.rate_limiter.clone();
        let client = self.client.clone();

        future_into_py(py, async move {
            let results = batch::send_batch(
                client,
                request_configs,
                concurrency,
                rate_limit,
                shared_limiter,
            )
            .await;

            let py_results: Vec<PyBatchResult> = results
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
                .collect();

            Ok(py_results)
        })
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
    fn download<'py>(
        &self,
        py: Python<'py>,
        url: String,
        path: String,
        max_size: Option<usize>,
        timeout: Option<u64>,
        verify_certs: Option<bool>,
        proxy: Option<String>,
        headers: Option<Vec<(String, String)>>,
        retries: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
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
            alpn_protocols: None,
            verbosity: 0,
        };

        let limiter = self.rate_limiter.clone();
        let client = self.client.clone();

        future_into_py(py, async move {
            if let Some(ref limiter) = limiter {
                limiter.acquire().await;
            }
            let response = client
                .send(&config)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.message))?;

            // Write body bytes to file
            let mut file = std::fs::File::create(&path).map_err(|e| {
                PyRuntimeError::new_err(format!("failed to create file '{}': {}", path, e))
            })?;
            file.write_all(&response.body_bytes).map_err(|e| {
                PyRuntimeError::new_err(format!("failed to write to '{}': {}", path, e))
            })?;

            Ok(path)
        })
    }

    /// Open a raw TCP or TLS connection to the target URL. Returns a
    /// RawConnection handle the caller can send arbitrary bytes over and
    /// read arbitrary bytes from, bypassing HTTP framing entirely.
    ///
    /// The URL's scheme (`http://` or `https://`) decides TCP vs TLS. Path
    /// and query are ignored at connect time.
    ///
    /// If a rate limit is set on this BlastHTTP instance, opening a raw
    /// connection consumes one rate-limit token.
    #[pyo3(signature = (
        url,
        verify_certs=None,
        cipher_string=None,
        min_tls_version=None,
        max_tls_version=None,
        resolve_ip=None,
        proxy=None,
        alpn_protocols=None,
    ))]
    fn raw_connect<'py>(
        &self,
        py: Python<'py>,
        url: String,
        verify_certs: Option<bool>,
        cipher_string: Option<String>,
        min_tls_version: Option<String>,
        max_tls_version: Option<String>,
        resolve_ip: Option<String>,
        proxy: Option<String>,
        alpn_protocols: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut config = RequestConfig::new(url.clone());
        config.verify_certs = verify_certs;
        config.cipher_string = cipher_string;
        config.min_tls_version = min_tls_version;
        config.max_tls_version = max_tls_version;
        config.resolve_ip = resolve_ip;
        config.proxy = proxy;
        config.alpn_protocols = alpn_protocols;

        let limiter = self.rate_limiter.clone();

        future_into_py(py, async move {
            if let Some(ref limiter) = limiter {
                limiter.acquire().await;
            }
            let conn = raw::RawConnection::connect(&url, &config)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.message))?;
            Ok(PyRawConnection {
                inner: Arc::new(conn),
            })
        })
    }
}

// ── RawConnection ─────────────────────────────────────────────────

#[pyclass(name = "RawConnection")]
struct PyRawConnection {
    inner: Arc<raw::RawConnection>,
}

#[pymethods]
impl PyRawConnection {
    /// Write arbitrary bytes to the connection. No framing, no validation.
    fn send_bytes<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            inner
                .send_bytes(&data)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.message))?;
            Ok(())
        })
    }

    /// Read up to `max_bytes` from the connection. Returns whatever bytes
    /// were available within `timeout_ms`. An empty return means either
    /// the timeout elapsed with no data or the peer closed the connection.
    /// Pass `timeout_ms=None` to wait indefinitely.
    #[pyo3(signature = (max_bytes, timeout_ms=None))]
    fn read_raw<'py>(
        &self,
        py: Python<'py>,
        max_bytes: usize,
        timeout_ms: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let data = inner
                .read_raw(max_bytes, timeout_ms)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.message))?;
            Ok(data)
        })
    }

    /// Close the connection. Subsequent send_bytes / read_raw calls error.
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            inner
                .close()
                .await
                .map_err(|e| PyRuntimeError::new_err(e.message))?;
            Ok(())
        })
    }

    /// Certificate info from the TLS handshake, if any.
    #[getter]
    fn cert_info(&self) -> Option<PyCertInfo> {
        self.inner.cert_info().map(|ci| PyCertInfo { inner: ci })
    }

    /// The ALPN protocol the server selected during the TLS handshake.
    /// None for plain HTTP, or for HTTPS connections where the server
    /// didn't advertise ALPN. Common values: "h2", "http/1.1".
    #[getter]
    fn negotiated_alpn(&self) -> Option<String> {
        self.inner.negotiated_alpn()
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
            alpn_protocols: None,
            verbosity: 0,
        }
    }
}

// ── H2 permissive-probe bindings (blasthttp.h2 submodule) ─────────

use crate::h2;

/// Python-side Header with all permissiveness knobs exposed as
/// optional keyword args. `str` values are UTF-8-encoded to `bytes`;
/// callers wanting raw non-UTF8 bytes pass `bytes` directly.
#[pyclass(name = "Header", module = "blasthttp.h2")]
#[derive(Clone)]
struct PyH2Header {
    inner: h2::Header,
}

fn parse_indexing(s: Option<&str>) -> PyResult<h2::Indexing> {
    match s {
        None | Some("with") => Ok(h2::Indexing::With),
        Some("without") => Ok(h2::Indexing::Without),
        Some("never") => Ok(h2::Indexing::Never),
        Some(other) => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "indexing must be one of 'with', 'without', 'never' (got {:?})",
            other,
        ))),
    }
}

fn bytes_from_py(obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    use pyo3::types::{PyBytes, PyString};
    if let Ok(s) = obj.downcast::<PyString>() {
        Ok(s.to_str()?.as_bytes().to_vec())
    } else if let Ok(b) = obj.downcast::<PyBytes>() {
        Ok(b.as_bytes().to_vec())
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "expected str or bytes",
        ))
    }
}

#[pymethods]
impl PyH2Header {
    #[new]
    #[pyo3(signature = (
        name, value, *,
        indexing = None,
        huffman_name = None,
        huffman_value = None,
        allow_invalid_value = false,
        allow_invalid_name = false,
        length_bloat_name = 0,
        length_bloat_value = 0,
        force_static_index = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        name: &Bound<'_, PyAny>,
        value: &Bound<'_, PyAny>,
        indexing: Option<&str>,
        huffman_name: Option<bool>,
        huffman_value: Option<bool>,
        allow_invalid_value: bool,
        allow_invalid_name: bool,
        length_bloat_name: u8,
        length_bloat_value: u8,
        force_static_index: Option<u8>,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: h2::Header {
                name: bytes_from_py(name)?,
                value: bytes_from_py(value)?,
                indexing: parse_indexing(indexing)?,
                huffman_name,
                huffman_value,
                allow_invalid_value,
                allow_invalid_name,
                length_bloat_name,
                length_bloat_value,
                force_static_index,
            },
        })
    }

    fn __repr__(&self) -> String {
        let name = String::from_utf8_lossy(&self.inner.name);
        let value = String::from_utf8_lossy(&self.inner.value);
        format!("Header(name={:?}, value={:?})", name, value)
    }
}

fn h2_encode_err_to_py(e: h2::EncodeError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(e.to_string())
}

/// Encode a list of Header objects into an HPACK header-block-fragment.
/// Returns bytes. Raises ValueError on permissiveness-gated validation
/// errors.
#[pyfunction]
fn h2_encode_headers(py: Python<'_>, headers: Vec<PyH2Header>) -> PyResult<PyObject> {
    let rust_headers: Vec<h2::Header> = headers.into_iter().map(|h| h.inner).collect();
    let out = h2::hpack::encode_headers(&rust_headers).map_err(h2_encode_err_to_py)?;
    Ok(pyo3::types::PyBytes::new(py, &out).into())
}

/// High-level probe builder: preface + SETTINGS + HEADERS (+ optional
/// CONTINUATION splits) + optional DATA. Every knob from the Rust
/// `ProbeOpts` is exposed as a keyword argument.
#[pyfunction]
#[pyo3(signature = (
    headers,
    body = None,
    *,
    send_preface = true,
    preface_override = None,
    settings = None,
    omit_settings = false,
    stream_id = 1,
    split_headers_after = None,
    pad_headers = 0,
    pad_data = 0,
    priority = None,
    force_no_end_stream_on_headers = false,
    extra_frames_before_headers = None,
    extra_frames_after = None,
))]
#[allow(clippy::too_many_arguments)]
fn h2_build_probe(
    py: Python<'_>,
    headers: Vec<PyH2Header>,
    body: Option<Vec<u8>>,
    send_preface: bool,
    preface_override: Option<Vec<u8>>,
    settings: Option<Vec<(u16, u32)>>,
    omit_settings: bool,
    stream_id: u32,
    split_headers_after: Option<usize>,
    pad_headers: u8,
    pad_data: u8,
    priority: Option<(u32, u8, bool)>,
    force_no_end_stream_on_headers: bool,
    extra_frames_before_headers: Option<Vec<u8>>,
    extra_frames_after: Option<Vec<u8>>,
) -> PyResult<PyObject> {
    let rust_headers: Vec<h2::Header> = headers.into_iter().map(|h| h.inner).collect();
    let opts = h2::ProbeOpts {
        send_preface,
        preface_override,
        // `settings=None` with `omit_settings=false` = default empty
        // SETTINGS. `omit_settings=true` = no SETTINGS frame at all.
        settings: if omit_settings {
            None
        } else {
            Some(settings.unwrap_or_default())
        },
        stream_id,
        body,
        split_headers_after,
        pad_headers,
        pad_data,
        priority,
        force_no_end_stream_on_headers,
        extra_frames_before_headers: extra_frames_before_headers.unwrap_or_default(),
        extra_frames_after: extra_frames_after.unwrap_or_default(),
    };
    let out = h2::probe::build_probe(&rust_headers, &opts).map_err(h2_encode_err_to_py)?;
    Ok(pyo3::types::PyBytes::new(py, &out).into())
}

// ── Tier 2 frame-level primitives (advanced researcher-use) ───────

#[pyfunction]
fn h2_build_raw_frame(
    py: Python<'_>, frame_type: u8, flags: u8, stream_id: u32, payload: Vec<u8>,
) -> PyObject {
    pyo3::types::PyBytes::new(py, &h2::frame::build_raw_frame(frame_type, flags, stream_id, &payload)).into()
}

#[pyfunction]
#[pyo3(signature = (settings = None, ack = false))]
fn h2_build_settings_frame(
    py: Python<'_>, settings: Option<Vec<(u16, u32)>>, ack: bool,
) -> PyObject {
    let s = settings.unwrap_or_default();
    pyo3::types::PyBytes::new(py, &h2::frame::build_settings_frame(&s, ack)).into()
}

#[pyfunction]
#[pyo3(signature = (
    header_block, stream_id = 1, end_stream = false, end_headers = true,
    padding = 0, priority = None,
))]
#[allow(clippy::too_many_arguments)]
fn h2_build_headers_frame(
    py: Python<'_>,
    header_block: Vec<u8>,
    stream_id: u32,
    end_stream: bool,
    end_headers: bool,
    padding: u8,
    priority: Option<(u32, u8, bool)>,
) -> PyObject {
    let out = h2::frame::build_headers_frame(h2::frame::HeadersFrameOpts {
        header_block: &header_block,
        stream_id,
        end_stream,
        end_headers,
        padding,
        priority,
    });
    pyo3::types::PyBytes::new(py, &out).into()
}

#[pyfunction]
#[pyo3(signature = (header_block, stream_id = 1, end_headers = true))]
fn h2_build_continuation_frame(
    py: Python<'_>, header_block: Vec<u8>, stream_id: u32, end_headers: bool,
) -> PyObject {
    pyo3::types::PyBytes::new(py, &h2::frame::build_continuation_frame(
        &header_block, stream_id, end_headers,
    )).into()
}

#[pyfunction]
#[pyo3(signature = (data, stream_id = 1, end_stream = true, padding = 0))]
fn h2_build_data_frame(
    py: Python<'_>, data: Vec<u8>, stream_id: u32, end_stream: bool, padding: u8,
) -> PyObject {
    pyo3::types::PyBytes::new(py, &h2::frame::build_data_frame(
        &data, stream_id, end_stream, padding,
    )).into()
}

#[pyfunction]
#[pyo3(signature = (increment, stream_id = 0))]
fn h2_build_window_update_frame(py: Python<'_>, increment: u32, stream_id: u32) -> PyObject {
    pyo3::types::PyBytes::new(py, &h2::frame::build_window_update_frame(increment, stream_id)).into()
}

#[pyfunction]
#[pyo3(signature = (data = None, ack = false))]
fn h2_build_ping_frame(py: Python<'_>, data: Option<Vec<u8>>, ack: bool) -> PyObject {
    let d = data.unwrap_or_else(|| vec![0; 8]);
    let mut arr = [0u8; 8];
    for (i, b) in d.iter().take(8).enumerate() {
        arr[i] = *b;
    }
    pyo3::types::PyBytes::new(py, &h2::frame::build_ping_frame(arr, ack)).into()
}

#[pyfunction]
#[pyo3(signature = (stream_id, error_code = 0))]
fn h2_build_rst_stream_frame(py: Python<'_>, stream_id: u32, error_code: u32) -> PyObject {
    pyo3::types::PyBytes::new(py, &h2::frame::build_rst_stream_frame(stream_id, error_code)).into()
}

#[pyfunction]
#[pyo3(signature = (last_stream_id = 0, error_code = 0, debug_data = None))]
fn h2_build_goaway_frame(
    py: Python<'_>, last_stream_id: u32, error_code: u32, debug_data: Option<Vec<u8>>,
) -> PyObject {
    let d = debug_data.unwrap_or_default();
    pyo3::types::PyBytes::new(py, &h2::frame::build_goaway_frame(
        last_stream_id, error_code, &d,
    )).into()
}

#[pyfunction]
#[pyo3(signature = (stream_id, dep_stream, weight, exclusive = false))]
fn h2_build_priority_frame(
    py: Python<'_>, stream_id: u32, dep_stream: u32, weight: u8, exclusive: bool,
) -> PyObject {
    pyo3::types::PyBytes::new(py, &h2::frame::build_priority_frame(
        stream_id, dep_stream, weight, exclusive,
    )).into()
}


fn register_h2_submodule<'py>(
    parent: &Bound<'py, PyModule>,
) -> PyResult<()> {
    let py = parent.py();
    let h2m = PyModule::new(py, "h2")?;
    h2m.add_class::<PyH2Header>()?;
    h2m.add("PREFACE", pyo3::types::PyBytes::new(py, h2::frame::PREFACE))?;
    // Frame-type constants (for when callers construct raw frames).
    h2m.add("FRAME_DATA", h2::frame::FRAME_DATA)?;
    h2m.add("FRAME_HEADERS", h2::frame::FRAME_HEADERS)?;
    h2m.add("FRAME_PRIORITY", h2::frame::FRAME_PRIORITY)?;
    h2m.add("FRAME_RST_STREAM", h2::frame::FRAME_RST_STREAM)?;
    h2m.add("FRAME_SETTINGS", h2::frame::FRAME_SETTINGS)?;
    h2m.add("FRAME_PING", h2::frame::FRAME_PING)?;
    h2m.add("FRAME_GOAWAY", h2::frame::FRAME_GOAWAY)?;
    h2m.add("FRAME_WINDOW_UPDATE", h2::frame::FRAME_WINDOW_UPDATE)?;
    h2m.add("FRAME_CONTINUATION", h2::frame::FRAME_CONTINUATION)?;
    // Flag bits.
    h2m.add("FLAG_END_STREAM", h2::frame::FLAG_END_STREAM)?;
    h2m.add("FLAG_ACK", h2::frame::FLAG_ACK)?;
    h2m.add("FLAG_END_HEADERS", h2::frame::FLAG_END_HEADERS)?;
    h2m.add("FLAG_PADDED", h2::frame::FLAG_PADDED)?;
    h2m.add("FLAG_PRIORITY", h2::frame::FLAG_PRIORITY)?;
    // SETTINGS identifiers.
    h2m.add("SETTINGS_HEADER_TABLE_SIZE", h2::frame::SETTINGS_HEADER_TABLE_SIZE)?;
    h2m.add("SETTINGS_ENABLE_PUSH", h2::frame::SETTINGS_ENABLE_PUSH)?;
    h2m.add("SETTINGS_MAX_CONCURRENT_STREAMS", h2::frame::SETTINGS_MAX_CONCURRENT_STREAMS)?;
    h2m.add("SETTINGS_INITIAL_WINDOW_SIZE", h2::frame::SETTINGS_INITIAL_WINDOW_SIZE)?;
    h2m.add("SETTINGS_MAX_FRAME_SIZE", h2::frame::SETTINGS_MAX_FRAME_SIZE)?;
    h2m.add("SETTINGS_MAX_HEADER_LIST_SIZE", h2::frame::SETTINGS_MAX_HEADER_LIST_SIZE)?;
    // Functions.
    h2m.add_function(pyo3::wrap_pyfunction!(h2_encode_headers, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_probe, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_raw_frame, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_settings_frame, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_headers_frame, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_continuation_frame, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_data_frame, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_window_update_frame, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_ping_frame, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_rst_stream_frame, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_goaway_frame, &h2m)?)?;
    h2m.add_function(pyo3::wrap_pyfunction!(h2_build_priority_frame, &h2m)?)?;
    // Expose friendly names without the `h2_` prefix.
    h2m.setattr("encode_headers", h2m.getattr("h2_encode_headers")?)?;
    h2m.setattr("build_probe", h2m.getattr("h2_build_probe")?)?;
    h2m.setattr("build_raw_frame", h2m.getattr("h2_build_raw_frame")?)?;
    h2m.setattr("build_settings_frame", h2m.getattr("h2_build_settings_frame")?)?;
    h2m.setattr("build_headers_frame", h2m.getattr("h2_build_headers_frame")?)?;
    h2m.setattr("build_continuation_frame", h2m.getattr("h2_build_continuation_frame")?)?;
    h2m.setattr("build_data_frame", h2m.getattr("h2_build_data_frame")?)?;
    h2m.setattr("build_window_update_frame", h2m.getattr("h2_build_window_update_frame")?)?;
    h2m.setattr("build_ping_frame", h2m.getattr("h2_build_ping_frame")?)?;
    h2m.setattr("build_rst_stream_frame", h2m.getattr("h2_build_rst_stream_frame")?)?;
    h2m.setattr("build_goaway_frame", h2m.getattr("h2_build_goaway_frame")?)?;
    h2m.setattr("build_priority_frame", h2m.getattr("h2_build_priority_frame")?)?;
    // Both `parent.add()` to attach as parent attribute AND register
    // in sys.modules so `import blasthttp.h2` finds it.
    parent.add("h2", &h2m)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("blasthttp.h2", h2m)?;
    Ok(())
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
    m.add_class::<PyRawConnection>()?;
    register_h2_submodule(m)?;
    Ok(())
}
