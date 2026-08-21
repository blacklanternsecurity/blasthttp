// Native Python bindings via PyO3.
// Wrapper types ("waitstaff") present Rust internals to Python as native classes.
// Kept separate from Rust structs so the Python API can diverge freely
// (e.g. complex request builders for Phase 4 raw byte control).

use futures::stream::{Stream, StreamExt};
use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration};
use pyo3::prelude::*;
use pyo3_async_runtimes::tokio::future_into_py;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::Instant;

use crate::batch::{self, BatchResult, RateLimiter};
use crate::client::HttpClient;
use crate::client::hyper::HyperClient;
use crate::client::raw;
use crate::config::RequestConfig;
use crate::multipart;
use crate::response::{CertInfo, RedirectHop, Response, ResponseHash};

use std::io::Write;

// ── Shared body/files coercion ────────────────────────────────────

/// Coerce a `body=` Python value (bytes, str, or None) to `Option<Vec<u8>>`.
pub(crate) fn coerce_body(body: Option<Bound<'_, PyAny>>) -> PyResult<Option<Vec<u8>>> {
    let Some(b) = body else {
        return Ok(None);
    };
    if b.is_none() {
        return Ok(None);
    }
    if let Ok(s) = b.extract::<String>() {
        return Ok(Some(s.into_bytes()));
    }
    if let Ok(bs) = b.extract::<Vec<u8>>() {
        return Ok(Some(bs));
    }
    Err(pyo3::exceptions::PyTypeError::new_err(
        "body must be bytes, str, or None",
    ))
}

pub(crate) type BodyAndHeaders = (Option<Vec<u8>>, Option<Vec<(String, String)>>);

/// Reject the combination of a non-None `body=` and a non-None `files=`.
/// Used by every entry point that accepts both kwargs.
pub(crate) fn reject_body_with_files(
    body: &Option<Bound<'_, PyAny>>,
    files: &Option<Bound<'_, PyAny>>,
) -> PyResult<()> {
    let body_set = body.as_ref().is_some_and(|b| !b.is_none());
    let files_set = files.as_ref().is_some_and(|f| !f.is_none());
    if body_set && files_set {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "got both body= and files=; pass only one",
        ));
    }
    Ok(())
}

/// Resolve `body=` / `files=` into the final body bytes + header list.
/// Passing both is rejected with `ValueError`. When `files` is set, the
/// multipart body is built and a `Content-Type: multipart/form-data;
/// boundary=...` header is appended unless the caller already supplied one.
pub(crate) fn apply_body_and_files(
    body: Option<Bound<'_, PyAny>>,
    files: Option<Bound<'_, PyAny>>,
    headers: Option<Vec<(String, String)>>,
) -> PyResult<BodyAndHeaders> {
    reject_body_with_files(&body, &files)?;
    if let Some(files) = files
        && !files.is_none()
    {
        let (boundary, body_bytes) = multipart::build_multipart(&files)?;
        let mut header_list = headers.unwrap_or_default();
        if !header_list
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            header_list.push((
                "Content-Type".to_string(),
                format!("multipart/form-data; boundary={}", boundary),
            ));
        }
        return Ok((Some(body_bytes), Some(header_list)));
    }
    Ok((coerce_body(body)?, headers))
}

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
    /// Build a RedirectHop from canned data — primarily for tests and
    /// fixture mocks that need to synthesize a redirect chain.
    #[new]
    #[pyo3(signature = (url, status, peer_ip=None))]
    fn new(url: String, status: u16, peer_ip: Option<String>) -> Self {
        PyRedirectHop {
            inner: RedirectHop {
                url,
                status,
                peer_ip,
            },
        }
    }

    #[getter]
    fn url(&self) -> String {
        self.inner.url.clone()
    }
    #[getter]
    fn status(&self) -> u16 {
        self.inner.status
    }
    /// IP actually used for this hop's TCP connection.
    /// None if the request went through a proxy.
    #[getter]
    fn peer_ip(&self) -> Option<String> {
        self.inner.peer_ip.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "RedirectHop(url='{}', status={}, peer_ip={:?})",
            self.inner.url, self.inner.status, self.inner.peer_ip,
        )
    }
}

// ── Headers (case-insensitive dict-like) ──────────────────────────

/// Case-insensitive headers view, mutable. Lookups (`h["Content-Type"]`
/// or `h["content-type"]`) hit the same entry. Iteration yields
/// lower-cased unique keys (Python dict / httpx convention). Use
/// `.items()` to iterate `(name, value)` tuples preserving original
/// case and duplicate names (e.g. multiple `Set-Cookie`).
#[pyclass(name = "Headers", mapping)]
pub struct PyHeaders {
    /// Original list (preserves order, original casing, duplicates).
    list: Vec<(String, String)>,
    /// Lower-case key → last-value-wins (used for direct lookup).
    lookup: HashMap<String, String>,
}

impl PyHeaders {
    fn from_list(list: Vec<(String, String)>) -> Self {
        let mut lookup = HashMap::with_capacity(list.len());
        for (k, v) in &list {
            lookup.insert(k.to_ascii_lowercase(), v.clone());
        }
        PyHeaders { list, lookup }
    }
}

#[pymethods]
impl PyHeaders {
    #[new]
    fn new(headers: Option<Vec<(String, String)>>) -> Self {
        Self::from_list(headers.unwrap_or_default())
    }

    fn __getitem__(&self, key: &str) -> PyResult<String> {
        self.lookup
            .get(&key.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(key.to_string()))
    }

    fn __setitem__(&mut self, key: String, value: String) {
        let lower = key.to_ascii_lowercase();
        // Drop any existing entries with this name (case-insensitive).
        self.list.retain(|(k, _)| !k.eq_ignore_ascii_case(&key));
        self.list.push((key, value.clone()));
        self.lookup.insert(lower, value);
    }

    fn __delitem__(&mut self, key: &str) -> PyResult<()> {
        let lower = key.to_ascii_lowercase();
        if self.lookup.remove(&lower).is_none() {
            return Err(pyo3::exceptions::PyKeyError::new_err(key.to_string()));
        }
        self.list.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
        Ok(())
    }

    fn __contains__(&self, key: &str) -> bool {
        self.lookup.contains_key(&key.to_ascii_lowercase())
    }

    fn __len__(&self) -> usize {
        self.lookup.len()
    }

    /// Iterate over lower-cased unique keys (Python dict convention).
    fn __iter__<'py>(slf: PyRef<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let py = slf.py();
        let keys: Vec<String> = slf.lookup.keys().cloned().collect();
        let list = pyo3::types::PyList::new(py, keys)?;
        Ok(list.try_iter()?.into_any())
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        // Compare against another PyHeaders or a Python dict.
        if let Ok(other_h) = other.cast::<PyHeaders>() {
            return Ok(self.lookup == other_h.borrow().lookup);
        }
        if let Ok(d) = other.cast::<pyo3::types::PyDict>() {
            // Lower-case both sides before comparing.
            let mut other_map = HashMap::with_capacity(d.len());
            for (k, v) in d.iter() {
                let k_str: String = k.extract()?;
                let v_str: String = v.extract()?;
                other_map.insert(k_str.to_ascii_lowercase(), v_str);
            }
            return Ok(self.lookup == other_map);
        }
        Ok(false)
    }

    fn __repr__(&self) -> String {
        format!("Headers({:?})", self.list)
    }

    /// `(name, value)` pairs preserving original casing and duplicates.
    fn items(&self) -> Vec<(String, String)> {
        self.list.clone()
    }

    /// Lower-cased unique keys.
    fn keys(&self) -> Vec<String> {
        self.lookup.keys().cloned().collect()
    }

    /// Values corresponding to the unique keys (last-value-wins).
    fn values(&self) -> Vec<String> {
        self.lookup.values().cloned().collect()
    }

    /// Case-insensitive lookup with default.
    #[pyo3(signature = (key, default=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        if let Some(v) = self.lookup.get(&key.to_ascii_lowercase()) {
            return Ok(Some(v.clone().into_py_any(py)?));
        }
        Ok(default)
    }
}

// ── Request (httpx-style request companion) ───────────────────────

/// Minimal request-side companion to a Response. Exposes the
/// originally-requested URL and HTTP method — useful for logging
/// and for consumers that follow the httpx API (`r.request.url`).
#[pyclass(name = "Request")]
pub struct PyRequest {
    #[pyo3(get)]
    url: String,
    #[pyo3(get)]
    method: String,
}

#[pymethods]
impl PyRequest {
    fn __repr__(&self) -> String {
        format!("Request(method='{}', url='{}')", self.method, self.url)
    }
}

// ── HTTPStatusError exception ─────────────────────────────────────

pyo3::create_exception!(
    blasthttp,
    HTTPStatusError,
    pyo3::exceptions::PyException,
    "Raised by Response.raise_for_status() when the response status is 4xx or 5xx."
);

// ── Response wrapper ──────────────────────────────────────────────

#[pyclass(name = "Response")]
pub struct PyResponse {
    pub(crate) inner: Response,
    /// Cached headers wrapper. Built on first access and reused so
    /// mutations (`r.headers["x"] = "y"`) persist across reads.
    headers_cache: OnceLock<Py<PyHeaders>>,
    /// Cached Request companion. `r.request is r.request` is True.
    request_cache: OnceLock<Py<PyRequest>>,
}

impl PyResponse {
    /// Build a PyResponse from a Rust `Response`. Used by both the
    /// hyper client wrapping paths and the mock submodule.
    pub fn wrap(inner: Response) -> Self {
        PyResponse {
            inner,
            headers_cache: OnceLock::new(),
            request_cache: OnceLock::new(),
        }
    }
}

#[pymethods]
impl PyResponse {
    /// Build a Response from canned data — primarily for tests and
    /// fixture mocks. Only `url` and `status` are required; everything
    /// else defaults to a plausibly-empty value.
    ///
    /// `body` accepts `bytes`, `str`, or `None` (treated as empty
    /// bytes). `headers` is a list of `(name, value)` tuples preserving
    /// order and duplicates. `redirect_chain` is a list of
    /// `RedirectHop` instances. `cert_info` is a `CertInfo` instance
    /// or None.
    ///
    /// `request_url` defaults to `url` (i.e. the response is for the
    /// final URL — set explicitly if simulating redirects).
    #[new]
    #[pyo3(signature = (
        url,
        status,
        headers=None,
        body=None,
        request_url=None,
        request_method=None,
        elapsed_ms=0,
        peer_ip=None,
        redirect_chain=None,
        cert_info=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        url: String,
        status: u16,
        headers: Option<Vec<(String, String)>>,
        body: Option<Bound<'_, PyAny>>,
        request_url: Option<String>,
        request_method: Option<String>,
        elapsed_ms: u64,
        peer_ip: Option<String>,
        redirect_chain: Option<Vec<PyRef<'_, PyRedirectHop>>>,
        cert_info: Option<PyRef<'_, PyCertInfo>>,
    ) -> PyResult<Self> {
        // Coerce body into Vec<u8> (accept bytes, str, or None).
        let body_bytes = match body {
            None => Vec::new(),
            Some(b) => {
                if let Ok(s) = b.extract::<String>() {
                    s.into_bytes()
                } else if let Ok(bs) = b.extract::<Vec<u8>>() {
                    bs
                } else {
                    return Err(pyo3::exceptions::PyTypeError::new_err(
                        "body must be bytes, str, or None",
                    ));
                }
            }
        };
        let _ = py; // currently unused but kept for future ergonomic helpers
        let request_url = request_url.unwrap_or_else(|| url.clone());
        let request_method = request_method.unwrap_or_else(|| "GET".to_string());
        let inner = Response {
            url,
            status,
            headers: headers.unwrap_or_default(),
            body_bytes,
            elapsed_ms,
            redirect_chain: redirect_chain
                .map(|hops| hops.into_iter().map(|h| h.inner.clone()).collect())
                .unwrap_or_default(),
            cert_info: cert_info.map(|c| c.inner.clone()),
            peer_ip,
            request_url,
            request_method,
            debug_log: Vec::new(),
            decode_error: None,
            body_cache: OnceLock::new(),
            raw_headers_cache: OnceLock::new(),
            cookies_cache: OnceLock::new(),
            hash_cache: OnceLock::new(),
        };
        Ok(PyResponse {
            inner,
            headers_cache: OnceLock::new(),
            request_cache: OnceLock::new(),
        })
    }

    #[getter]
    fn url(&self) -> String {
        self.inner.url.clone()
    }
    #[getter]
    fn status(&self) -> u16 {
        self.inner.status
    }
    /// httpx-style alias for `status`. Returns the same integer.
    #[getter]
    fn status_code(&self) -> u16 {
        self.inner.status
    }
    /// `True` for status codes in the 2xx-3xx range.
    #[getter]
    fn is_success(&self) -> bool {
        self.inner.is_success()
    }
    /// UTF-8 decoded body. Same as `text`. Lazily decoded — not paid
    /// for unless read.
    #[getter]
    fn body(&self) -> &str {
        self.inner.body()
    }
    /// httpx-style alias for `body` — UTF-8 decoded body.
    #[getter]
    fn text(&self) -> &str {
        self.inner.body()
    }
    #[getter]
    fn elapsed_ms(&self) -> u64 {
        self.inner.elapsed_ms
    }

    /// httpx-style `elapsed` as a `datetime.timedelta`.
    #[getter]
    fn elapsed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyDelta>> {
        let ms = self.inner.elapsed_ms as i32;
        let seconds = ms / 1000;
        let microseconds = (ms % 1000) * 1000;
        pyo3::types::PyDelta::new(py, 0, seconds, microseconds, false)
    }

    /// Raw body as Python bytes (avoids UTF-8 decode for binary responses)
    #[getter]
    fn body_bytes(&self) -> &[u8] {
        &self.inner.body_bytes
    }

    /// httpx-style alias for `body_bytes` — raw body as Python bytes.
    #[getter]
    fn content(&self) -> &[u8] {
        &self.inner.body_bytes
    }

    /// Why `content` is not decoded content, when it isn't.
    ///
    /// `None` on any ordinary response, including one with no
    /// `Content-Encoding`. A string means `content` is not what the header
    /// said it was, and says how far decoding got: exactly what the server
    /// sent, a stack only partly undone, or a stream that decoded partway
    /// and then reported damage or an early end. The response is worth
    /// keeping either way, but code that hashes, matches or diffs bodies
    /// should check this rather than treat those bytes as content.
    #[getter]
    fn decode_error(&self) -> Option<String> {
        self.inner.decode_error.clone()
    }

    /// The originally-requested URL and method (httpx-style
    /// `r.request.url` / `r.request.method`). Cached, so
    /// `r.request is r.request` is True.
    #[getter]
    fn request<'py>(&self, py: Python<'py>) -> PyResult<Py<PyRequest>> {
        if let Some(cached) = self.request_cache.get() {
            return Ok(cached.clone_ref(py));
        }
        let req = PyRequest {
            url: self.inner.request_url.clone(),
            method: self.inner.request_method.clone(),
        };
        let bound = Py::new(py, req)?;
        let _ = self.request_cache.set(bound.clone_ref(py));
        Ok(bound)
    }

    /// Response headers as a case-insensitive `Headers` view.
    /// The same instance is returned on every read, so mutations
    /// (`del r.headers["server"]`, `r.headers["x-foo"] = "bar"`)
    /// persist. Use `r.headers.items()` to iterate `(name, value)`
    /// tuples preserving original case and duplicate names.
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> PyResult<Py<PyHeaders>> {
        if let Some(cached) = self.headers_cache.get() {
            return Ok(cached.clone_ref(py));
        }
        let h = PyHeaders::from_list(self.inner.headers.clone());
        let bound = Py::new(py, h)?;
        // Set may race; if another thread won, just use that value.
        let _ = self.headers_cache.set(bound.clone_ref(py));
        Ok(bound)
    }

    /// Canonical `Name: Value\r\nName: Value` form of `headers`. Same
    /// string used to compute `hash.header_*`. Computed and cached on
    /// first access — repeated reads are free.
    #[getter]
    fn raw_headers(&self) -> &str {
        self.inner.raw_headers()
    }

    /// Cookies parsed from `Set-Cookie` headers as a `dict[str, str]`.
    /// Only the `name=value` pair before any attributes is kept; on
    /// duplicates the last `Set-Cookie` wins. Computed and cached on
    /// first access.
    #[getter]
    fn cookies(&self) -> HashMap<String, String> {
        self.inner.cookies().clone()
    }

    /// TLS certificate info (None for plain HTTP)
    #[getter]
    fn cert_info(&self) -> Option<PyCertInfo> {
        self.inner
            .cert_info
            .clone()
            .map(|c| PyCertInfo { inner: c })
    }

    /// IP actually used for the final hop's TCP connection.
    /// None if the request went through a proxy (the peer there is the
    /// proxy, not the target).
    #[getter]
    fn peer_ip(&self) -> Option<String> {
        self.inner.peer_ip.clone()
    }

    /// Content hashes for fingerprinting. Computed and cached on
    /// first access — md5+sha256+mmh3 of body and headers are real
    /// CPU work, so consumers that don't need them don't pay for them.
    #[getter]
    fn hash(&self) -> PyResponseHash {
        PyResponseHash {
            inner: self.inner.hash().clone(),
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

    /// Always `True`. Mirrors httpx — a Response object is truthy
    /// regardless of status, so `if response:` checks "did we get a
    /// response at all", not "was it successful". Use `is_success`
    /// or `raise_for_status()` for that.
    fn __bool__(&self) -> bool {
        true
    }

    /// Parse the body as JSON. Equivalent to `json.loads(response.text)`
    /// — raises `json.JSONDecodeError` on invalid JSON.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let json_module = py.import("json")?;
        json_module.call_method1("loads", (self.inner.body(),))
    }

    /// Raise `HTTPStatusError` if the status is 4xx or 5xx.
    /// No-op for 1xx-3xx. Mirrors httpx and requests.
    fn raise_for_status(slf: PyRef<'_, Self>) -> PyResult<()> {
        let status = slf.inner.status;
        if (400..600).contains(&status) {
            let msg = format!("HTTP {} for url '{}'", status, slf.inner.url);
            let py = slf.py();
            let err = HTTPStatusError::new_err(msg);
            // Attach the Response object on the exception so callers
            // can inspect it (httpx convention: `e.response`).
            let response_obj: Py<PyResponse> = slf.into();
            err.value(py).setattr("response", response_obj)?;
            return Err(err);
        }
        Ok(())
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
    /// Build a BatchResult from canned data — primarily for tests and
    /// fixture mocks. Provide either `response` (a Response instance)
    /// for success, or `error` (a string) for failure. Both default to
    /// None; passing neither yields a degenerate "no response, no error"
    /// result that `success` reports as False.
    #[new]
    #[pyo3(signature = (url, response=None, error=None))]
    fn new(url: String, response: Option<PyRef<'_, PyResponse>>, error: Option<String>) -> Self {
        PyBatchResult {
            url,
            response: response.map(|r| r.inner.clone()),
            error,
        }
    }

    #[getter]
    fn url(&self) -> String {
        self.url.clone()
    }

    /// The response object (None if the request failed)
    #[getter]
    fn response(&self) -> Option<PyResponse> {
        self.response.clone().map(|r| PyResponse {
            inner: r,
            headers_cache: OnceLock::new(),
            request_cache: OnceLock::new(),
        })
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

fn to_py_batch_result(r: BatchResult) -> PyBatchResult {
    let (response, error) = match r.result {
        Ok(resp) => (Some(resp), None),
        Err(e) => (None, Some(e.message)),
    };
    PyBatchResult {
        url: r.url,
        response,
        error,
    }
}

// ── Streaming batch iterator ──────────────────────────────────────

/// Async iterator exposed to Python for `request_batch_stream`. Each
/// `__anext__` drains the underlying stream into a batch (up to 1000
/// items or 200ms — whichever comes first) and returns the batch as a
/// `list[BatchResult]`. Callers iterate with:
///
/// ```text
/// async for batch in client.request_batch_stream(configs):
///     for r in batch:
///         ...
/// ```
///
/// Two reasons for batching at this boundary:
///   1. Throughput. Each `__anext__` is a full Python↔Rust round-trip
///      (`future_into_py`, GIL release/reacquire, asyncio scheduling).
///      At 100k+ QPS, paying that per result caps us roughly an order
///      of magnitude below non-streaming. Batching ~1000 amortizes it.
///   2. Streaming latency. The 200ms timeout is the actual streaming
///      property: even when results trickle in slowly, partial batches
///      flush after 200ms so the consumer is never starved.
///
/// Delicate bits (mirrors blastdns's PyBatchIterator — changing these
/// can deadlock Python's event loop or leak tasks):
///   • TokioMutex, not std::sync::Mutex: the guard crosses .await.
///   • future_into_py releases the GIL while polling; do NOT
///     Python::attach inside the loop.
///   • PyStopAsyncIteration is only raised when a NEW __anext__ call
///     finds both the stream empty AND the batch empty. If the stream
///     ends mid-batch, return what we have and let the next call raise.
#[pyclass(name = "BatchResultIterator")]
pub struct PyBatchResultIterator {
    inner: Arc<TokioMutex<Pin<Box<dyn Stream<Item = BatchResult> + Send>>>>,
}

#[pymethods]
impl PyBatchResultIterator {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);

        future_into_py(py, async move {
            let mut stream = inner.lock().await;
            let mut batch: Vec<PyBatchResult> = Vec::new();
            let start = Instant::now();
            let timeout = Duration::from_millis(200);

            loop {
                if batch.len() >= 1000 || (!batch.is_empty() && start.elapsed() >= timeout) {
                    return Ok(batch);
                }

                match stream.next().await {
                    Some(r) => batch.push(to_py_batch_result(r)),
                    None => {
                        if batch.is_empty() {
                            return Err(PyStopAsyncIteration::new_err("end of stream"));
                        } else {
                            return Ok(batch);
                        }
                    }
                }
            }
        })
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
    ///
    /// `body` accepts `bytes`, `str`, or `None`. `files` is an
    /// httpx-style dict mapping field name to content — when set, the
    /// body is built as a `multipart/form-data` payload and the
    /// `Content-Type` header is set automatically (unless the caller
    /// supplied one). `files` takes precedence over `body`.
    ///
    /// `redirect_cookies` (default `True`) applies a cookie set by one
    /// redirect hop to the hops after it, the way a browser does, which
    /// is what lets a login or bot-check page resolve. What the chain
    /// collects lives for that request only, so nothing carries into the
    /// next one. This is not a session: there is no cookie storage behind
    /// it and no state shared between requests.
    ///
    /// A cookie you send yourself always wins. If `headers` carries
    /// `Cookie: session=mine`, every hop sends `session=mine`, and a
    /// `Set-Cookie` for `session` is ignored rather than replacing it,
    /// deleting it, or going out beside it as a second value.
    ///
    /// `alpn_protocols` overrides what gets offered during the TLS
    /// handshake, and the request is then spoken over whatever the
    /// server picks from that list. Pass `["http/1.1"]` to keep a
    /// request off HTTP/2, which is what you want for a server that
    /// only answers correctly over HTTP/1.1, or `["h2"]` to force
    /// HTTP/2.
    ///
    /// The default differs by path, because the offer is part of the
    /// client's TLS fingerprint and changing it changes how every
    /// existing caller looks on the wire. Ordinary pooled requests
    /// offer `["h2", "http/1.1"]`. Requests with `resolve_ip` or
    /// `request_target` set bypass the pool and offer `["http/1.1"]`
    /// alone.
    ///
    /// `request_target` cannot be combined with an HTTP/2 offer: h2
    /// carries the target in `:path`, which is built from the URI, so
    /// there is no request-line to control. Use `raw_connect` with
    /// `blasthttp.h2` to write pseudo-headers directly.
    #[pyo3(signature = (
        url,
        method=None,
        headers=None,
        body=None,
        files=None,
        timeout=None,
        follow_redirects=None,
        max_redirects=None,
        redirect_cookies=None,
        verify_certs=None,
        proxy=None,
        no_proxy=None,
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
        alpn_protocols=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn request<'py>(
        &self,
        py: Python<'py>,
        url: String,
        method: Option<String>,
        headers: Option<Vec<(String, String)>>,
        body: Option<Bound<'py, PyAny>>,
        files: Option<Bound<'py, PyAny>>,
        timeout: Option<u64>,
        follow_redirects: Option<bool>,
        max_redirects: Option<u32>,
        redirect_cookies: Option<bool>,
        verify_certs: Option<bool>,
        proxy: Option<String>,
        no_proxy: Option<Vec<String>>,
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
        alpn_protocols: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (body_bytes, headers) = apply_body_and_files(body, files, headers)?;
        let config = RequestConfig {
            url,
            method,
            headers,
            body: body_bytes,
            timeout_seconds: timeout,
            max_body_size,
            follow_redirects,
            max_redirects,
            redirect_cookies,
            verify_certs,
            proxy,
            no_proxy: no_proxy.unwrap_or_default(),
            cipher_string,
            min_tls_version,
            max_tls_version,
            retries,
            retry_wait_min_ms,
            retry_wait_max_ms,
            raw_path,
            request_target,
            resolve_ip,
            alpn_protocols,
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
            Ok(PyResponse {
                inner: response,
                headers_cache: OnceLock::new(),
                request_cache: OnceLock::new(),
            })
        })
    }

    /// Send a batch of requests concurrently and await all of them.
    ///
    /// Returns a `list[BatchResult]` once every request has finished — the
    /// list is in input order, regardless of which requests completed
    /// first. Each `BatchResult` has `.url`, `.response` (or `None` on
    /// failure), and `.error` (or `None` on success).
    ///
    /// Use this when you want the full result set in one shot. Use
    /// `request_batch_stream` instead if you want to start processing
    /// results as soon as they complete (e.g. so a slow request doesn't
    /// block faster peers behind it).
    ///
    /// Example:
    ///
    /// ```text
    /// results = await client.request_batch(configs, concurrency=100)
    /// for r in results:
    ///     if r.success:
    ///         ...
    /// ```
    ///
    /// Args:
    ///   configs: List of `BatchConfig` objects describing each request.
    ///   concurrency: Maximum simultaneous in-flight requests. Default 50.
    ///   rate_limit: Optional cap on dispatch rate (requests/sec). `None`
    ///     means no per-call cap. If `set_rate_limit()` is also active on
    ///     the client, the more restrictive (lower RPS) limit wins.
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
            .map(|c| c.into_request_config(py))
            .collect::<PyResult<_>>()?;

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

            let py_results: Vec<PyBatchResult> =
                results.into_iter().map(to_py_batch_result).collect();

            Ok(py_results)
        })
    }

    /// Streaming variant of `request_batch`. Returns an async iterator
    /// that yields `list[BatchResult]` chunks as requests complete, in
    /// completion order — a slow request never blocks faster peers
    /// behind it in the input list.
    ///
    /// Each yielded chunk holds up to 1000 `BatchResult`s or up to ~200ms
    /// worth, whichever fills first; partial chunks flush on the timeout
    /// so the consumer is never starved when results trickle in slowly.
    /// The chunked shape is intentional — one boundary-crossing per
    /// chunk amortizes the per-`__anext__` overhead and lets streaming
    /// keep pace with the all-at-once `request_batch` throughput.
    ///
    /// Use this when you want to overlap consumer work with in-flight
    /// HTTP I/O, or when partial results are useful before the slowest
    /// request finishes. Use `request_batch` instead when you just want
    /// the whole list at the end.
    ///
    /// Example:
    ///
    /// ```text
    /// async for batch in client.request_batch_stream(configs, concurrency=100):
    ///     for r in batch:
    ///         if r.success:
    ///             ...
    /// ```
    ///
    /// Args:
    ///   configs: List of `BatchConfig` objects describing each request.
    ///   concurrency: Maximum simultaneous in-flight requests. Default 50.
    ///   rate_limit: Optional cap on dispatch rate (requests/sec). `None`
    ///     means no per-call cap. If `set_rate_limit()` is also active on
    ///     the client, the more restrictive (lower RPS) limit wins.
    #[pyo3(signature = (configs, concurrency=50, rate_limit=None))]
    fn request_batch_stream(
        &self,
        py: Python<'_>,
        configs: Vec<PyBatchConfig>,
        concurrency: usize,
        rate_limit: Option<f64>,
    ) -> PyResult<PyBatchResultIterator> {
        let request_configs: Vec<RequestConfig> = configs
            .into_iter()
            .map(|c| c.into_request_config(py))
            .collect::<PyResult<_>>()?;

        let stream = batch::send_batch_stream(
            self.client.clone(),
            request_configs,
            concurrency,
            rate_limit,
            self.rate_limiter.clone(),
        );

        Ok(PyBatchResultIterator {
            inner: Arc::new(TokioMutex::new(Box::pin(stream))),
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
        no_proxy=None,
        headers=None,
        retries=None,
        redirect_cookies=None,
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
        no_proxy: Option<Vec<String>>,
        headers: Option<Vec<(String, String)>>,
        retries: Option<u32>,
        redirect_cookies: Option<bool>,
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
            redirect_cookies,
            verify_certs,
            proxy,
            no_proxy: no_proxy.unwrap_or_default(),
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
    /// connection consumes one rate-limit token. The returned
    /// `RawConnection` inherits the same limiter, so every subsequent
    /// `send_bytes` / `read_raw` call on that handle also consumes a
    /// token — a single-connection caller can't burst past the limit.
    #[pyo3(signature = (
        url,
        verify_certs=None,
        cipher_string=None,
        min_tls_version=None,
        max_tls_version=None,
        resolve_ip=None,
        proxy=None,
        no_proxy=None,
        alpn_protocols=None,
        timeout=None,
    ))]
    #[allow(clippy::too_many_arguments)]
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
        no_proxy: Option<Vec<String>>,
        alpn_protocols: Option<Vec<String>>,
        timeout: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut config = RequestConfig::new(url.clone());
        config.verify_certs = verify_certs;
        config.cipher_string = cipher_string;
        config.min_tls_version = min_tls_version;
        config.max_tls_version = max_tls_version;
        config.resolve_ip = resolve_ip;
        config.proxy = proxy;
        config.no_proxy = no_proxy.unwrap_or_default();
        config.alpn_protocols = alpn_protocols;
        config.timeout_seconds = timeout;

        let limiter = self.rate_limiter.clone();
        // Hand the limiter to the PyRawConnection so send_bytes /
        // read_raw on that handle also consume tokens.
        let limiter_for_conn = limiter.clone();

        future_into_py(py, async move {
            if let Some(ref limiter) = limiter {
                limiter.acquire().await;
            }
            let conn = raw::RawConnection::connect(&url, &config)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.message))?;
            Ok(PyRawConnection {
                inner: Arc::new(conn),
                rate_limiter: limiter_for_conn,
            })
        })
    }
}

// ── RawConnection ─────────────────────────────────────────────────

#[pyclass(name = "RawConnection")]
struct PyRawConnection {
    inner: Arc<raw::RawConnection>,
    // Inherited from the BlastHTTP instance that opened the connection.
    // When set, every send_bytes / read_raw call acquires one token
    // from the limiter — not just the initial connect. This keeps a
    // caller that pipelines many ops on a single connection from
    // bursting past the configured rate.
    rate_limiter: Option<Arc<RateLimiter>>,
}

#[pymethods]
impl PyRawConnection {
    /// Write arbitrary bytes to the connection. No framing, no validation.
    ///
    /// If the originating BlastHTTP instance had a rate limit set,
    /// this call also consumes one rate-limit token.
    fn send_bytes<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let limiter = self.rate_limiter.clone();
        future_into_py(py, async move {
            if let Some(ref limiter) = limiter {
                limiter.acquire().await;
            }
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
    ///
    /// If the originating BlastHTTP instance had a rate limit set,
    /// this call also consumes one rate-limit token.
    #[pyo3(signature = (max_bytes, timeout_ms=None))]
    fn read_raw<'py>(
        &self,
        py: Python<'py>,
        max_bytes: usize,
        timeout_ms: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let limiter = self.rate_limiter.clone();
        future_into_py(py, async move {
            if let Some(ref limiter) = limiter {
                limiter.acquire().await;
            }
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

    /// IP actually used for this connection's TCP socket. None if the
    /// connection went through a proxy.
    #[getter]
    fn peer_ip(&self) -> Option<String> {
        self.inner.peer_ip()
    }
}

// ── Batch config input type ───────────────────────────────────────

/// Per-request config for batch operations.
/// Mirrors send() parameters but as a class for batch input.
#[pyclass(name = "BatchConfig")]
struct PyBatchConfig {
    #[pyo3(get, set)]
    url: String,
    #[pyo3(get, set)]
    method: Option<String>,
    #[pyo3(get, set)]
    headers: Option<Vec<(String, String)>>,
    #[pyo3(get, set)]
    body: Option<Py<PyAny>>,
    #[pyo3(get, set)]
    files: Option<Py<PyAny>>,
    #[pyo3(get, set)]
    timeout: Option<u64>,
    #[pyo3(get, set)]
    follow_redirects: Option<bool>,
    #[pyo3(get, set)]
    max_redirects: Option<u32>,
    #[pyo3(get, set)]
    redirect_cookies: Option<bool>,
    #[pyo3(get, set)]
    alpn_protocols: Option<Vec<String>>,
    #[pyo3(get, set)]
    verify_certs: Option<bool>,
    #[pyo3(get, set)]
    proxy: Option<String>,
    #[pyo3(get, set)]
    no_proxy: Option<Vec<String>>,
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
        files=None,
        timeout=None,
        follow_redirects=None,
        max_redirects=None,
        redirect_cookies=None,
        verify_certs=None,
        proxy=None,
        no_proxy=None,
        cipher_string=None,
        min_tls_version=None,
        max_tls_version=None,
        retries=None,
        retry_wait_min_ms=None,
        retry_wait_max_ms=None,
        raw_path=None,
        request_target=None,
        resolve_ip=None,
        alpn_protocols=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        url: String,
        method: Option<String>,
        headers: Option<Vec<(String, String)>>,
        body: Option<Bound<'_, PyAny>>,
        files: Option<Bound<'_, PyAny>>,
        timeout: Option<u64>,
        follow_redirects: Option<bool>,
        max_redirects: Option<u32>,
        redirect_cookies: Option<bool>,
        verify_certs: Option<bool>,
        proxy: Option<String>,
        no_proxy: Option<Vec<String>>,
        cipher_string: Option<String>,
        min_tls_version: Option<String>,
        max_tls_version: Option<String>,
        retries: Option<u32>,
        retry_wait_min_ms: Option<u64>,
        retry_wait_max_ms: Option<u64>,
        raw_path: Option<bool>,
        request_target: Option<String>,
        resolve_ip: Option<String>,
        alpn_protocols: Option<Vec<String>>,
    ) -> Self {
        PyBatchConfig {
            url,
            method,
            headers,
            body: body.map(|b| b.unbind()),
            files: files.map(|f| f.unbind()),
            timeout,
            follow_redirects,
            max_redirects,
            redirect_cookies,
            verify_certs,
            proxy,
            no_proxy,
            cipher_string,
            min_tls_version,
            max_tls_version,
            retries,
            retry_wait_min_ms,
            retry_wait_max_ms,
            raw_path,
            request_target,
            resolve_ip,
            alpn_protocols,
        }
    }
}

impl Clone for PyBatchConfig {
    fn clone(&self) -> Self {
        Python::attach(|py| PyBatchConfig {
            url: self.url.clone(),
            method: self.method.clone(),
            headers: self.headers.clone(),
            body: self.body.as_ref().map(|b| b.clone_ref(py)),
            files: self.files.as_ref().map(|f| f.clone_ref(py)),
            timeout: self.timeout,
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            redirect_cookies: self.redirect_cookies,
            verify_certs: self.verify_certs,
            proxy: self.proxy.clone(),
            no_proxy: self.no_proxy.clone(),
            cipher_string: self.cipher_string.clone(),
            min_tls_version: self.min_tls_version.clone(),
            max_tls_version: self.max_tls_version.clone(),
            retries: self.retries,
            retry_wait_min_ms: self.retry_wait_min_ms,
            retry_wait_max_ms: self.retry_wait_max_ms,
            raw_path: self.raw_path,
            request_target: self.request_target.clone(),
            resolve_ip: self.resolve_ip.clone(),
            alpn_protocols: self.alpn_protocols.clone(),
        })
    }
}

impl PyBatchConfig {
    fn into_request_config(self, py: Python<'_>) -> PyResult<RequestConfig> {
        let body = self.body.as_ref().map(|b| b.bind(py).clone());
        let files = self.files.as_ref().map(|f| f.bind(py).clone());
        let (body_bytes, headers) = apply_body_and_files(body, files, self.headers)?;
        Ok(RequestConfig {
            url: self.url,
            method: self.method,
            headers,
            body: body_bytes,
            timeout_seconds: self.timeout,
            max_body_size: None,
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            redirect_cookies: self.redirect_cookies,
            verify_certs: self.verify_certs,
            proxy: self.proxy,
            no_proxy: self.no_proxy.unwrap_or_default(),
            cipher_string: self.cipher_string,
            min_tls_version: self.min_tls_version,
            max_tls_version: self.max_tls_version,
            retries: self.retries,
            retry_wait_min_ms: self.retry_wait_min_ms,
            retry_wait_max_ms: self.retry_wait_max_ms,
            raw_path: self.raw_path,
            request_target: self.request_target,
            resolve_ip: self.resolve_ip,
            alpn_protocols: self.alpn_protocols,
            verbosity: 0,
        })
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
    if let Ok(s) = obj.cast::<PyString>() {
        Ok(s.to_str()?.as_bytes().to_vec())
    } else if let Ok(b) = obj.cast::<PyBytes>() {
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
fn h2_encode_headers(py: Python<'_>, headers: Vec<PyH2Header>) -> PyResult<Py<PyAny>> {
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
) -> PyResult<Py<PyAny>> {
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
    py: Python<'_>,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
) -> Py<PyAny> {
    pyo3::types::PyBytes::new(
        py,
        &h2::frame::build_raw_frame(frame_type, flags, stream_id, &payload),
    )
    .into()
}

#[pyfunction]
#[pyo3(signature = (settings = None, ack = false))]
fn h2_build_settings_frame(
    py: Python<'_>,
    settings: Option<Vec<(u16, u32)>>,
    ack: bool,
) -> Py<PyAny> {
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
) -> Py<PyAny> {
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
    py: Python<'_>,
    header_block: Vec<u8>,
    stream_id: u32,
    end_headers: bool,
) -> Py<PyAny> {
    pyo3::types::PyBytes::new(
        py,
        &h2::frame::build_continuation_frame(&header_block, stream_id, end_headers),
    )
    .into()
}

#[pyfunction]
#[pyo3(signature = (data, stream_id = 1, end_stream = true, padding = 0))]
fn h2_build_data_frame(
    py: Python<'_>,
    data: Vec<u8>,
    stream_id: u32,
    end_stream: bool,
    padding: u8,
) -> Py<PyAny> {
    pyo3::types::PyBytes::new(
        py,
        &h2::frame::build_data_frame(&data, stream_id, end_stream, padding),
    )
    .into()
}

#[pyfunction]
#[pyo3(signature = (increment, stream_id = 0))]
fn h2_build_window_update_frame(py: Python<'_>, increment: u32, stream_id: u32) -> Py<PyAny> {
    pyo3::types::PyBytes::new(
        py,
        &h2::frame::build_window_update_frame(increment, stream_id),
    )
    .into()
}

#[pyfunction]
#[pyo3(signature = (data = None, ack = false))]
fn h2_build_ping_frame(py: Python<'_>, data: Option<Vec<u8>>, ack: bool) -> Py<PyAny> {
    let d = data.unwrap_or_else(|| vec![0; 8]);
    let mut arr = [0u8; 8];
    for (i, b) in d.iter().take(8).enumerate() {
        arr[i] = *b;
    }
    pyo3::types::PyBytes::new(py, &h2::frame::build_ping_frame(arr, ack)).into()
}

#[pyfunction]
#[pyo3(signature = (stream_id, error_code = 0))]
fn h2_build_rst_stream_frame(py: Python<'_>, stream_id: u32, error_code: u32) -> Py<PyAny> {
    pyo3::types::PyBytes::new(
        py,
        &h2::frame::build_rst_stream_frame(stream_id, error_code),
    )
    .into()
}

#[pyfunction]
#[pyo3(signature = (last_stream_id = 0, error_code = 0, debug_data = None))]
fn h2_build_goaway_frame(
    py: Python<'_>,
    last_stream_id: u32,
    error_code: u32,
    debug_data: Option<Vec<u8>>,
) -> Py<PyAny> {
    let d = debug_data.unwrap_or_default();
    pyo3::types::PyBytes::new(
        py,
        &h2::frame::build_goaway_frame(last_stream_id, error_code, &d),
    )
    .into()
}

#[pyfunction]
#[pyo3(signature = (stream_id, dep_stream, weight, exclusive = false))]
fn h2_build_priority_frame(
    py: Python<'_>,
    stream_id: u32,
    dep_stream: u32,
    weight: u8,
    exclusive: bool,
) -> Py<PyAny> {
    pyo3::types::PyBytes::new(
        py,
        &h2::frame::build_priority_frame(stream_id, dep_stream, weight, exclusive),
    )
    .into()
}

// ── HPACK decoder binding ──────────────────────────────────────────

/// Python-exposed HPACK decoder. Holds dynamic-table state across
/// calls within one connection. Construct once per connection, call
/// `decode(block)` per HEADERS/CONTINUATION block.
#[pyclass(name = "Decoder", module = "blasthttp.h2")]
struct PyH2Decoder {
    inner: h2::hpack::Decoder,
}

fn h2_decode_err_to_py(e: h2::hpack::DecodeError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(e.to_string())
}

#[pymethods]
impl PyH2Decoder {
    #[new]
    #[pyo3(signature = (max_table_size = 4096))]
    fn new(max_table_size: u32) -> Self {
        Self {
            inner: h2::hpack::Decoder::with_max_table_size(max_table_size),
        }
    }

    /// Decode a header-block-fragment. Returns a list of
    /// (name: bytes, value: bytes) tuples.
    fn decode<'py>(
        &mut self,
        py: Python<'py>,
        block: Vec<u8>,
    ) -> PyResult<Vec<(Py<pyo3::types::PyBytes>, Py<pyo3::types::PyBytes>)>> {
        let pairs = self
            .inner
            .decode_headers(&block)
            .map_err(h2_decode_err_to_py)?;
        let mut out = Vec::with_capacity(pairs.len());
        for (n, v) in pairs {
            out.push((
                pyo3::types::PyBytes::new(py, &n).into(),
                pyo3::types::PyBytes::new(py, &v).into(),
            ));
        }
        Ok(out)
    }
}

fn register_h2_submodule<'py>(parent: &Bound<'py, PyModule>) -> PyResult<()> {
    let py = parent.py();
    let h2m = PyModule::new(py, "h2")?;
    h2m.add_class::<PyH2Header>()?;
    h2m.add_class::<PyH2Decoder>()?;
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
    h2m.add(
        "SETTINGS_HEADER_TABLE_SIZE",
        h2::frame::SETTINGS_HEADER_TABLE_SIZE,
    )?;
    h2m.add("SETTINGS_ENABLE_PUSH", h2::frame::SETTINGS_ENABLE_PUSH)?;
    h2m.add(
        "SETTINGS_MAX_CONCURRENT_STREAMS",
        h2::frame::SETTINGS_MAX_CONCURRENT_STREAMS,
    )?;
    h2m.add(
        "SETTINGS_INITIAL_WINDOW_SIZE",
        h2::frame::SETTINGS_INITIAL_WINDOW_SIZE,
    )?;
    h2m.add(
        "SETTINGS_MAX_FRAME_SIZE",
        h2::frame::SETTINGS_MAX_FRAME_SIZE,
    )?;
    h2m.add(
        "SETTINGS_MAX_HEADER_LIST_SIZE",
        h2::frame::SETTINGS_MAX_HEADER_LIST_SIZE,
    )?;
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
    h2m.setattr(
        "build_settings_frame",
        h2m.getattr("h2_build_settings_frame")?,
    )?;
    h2m.setattr(
        "build_headers_frame",
        h2m.getattr("h2_build_headers_frame")?,
    )?;
    h2m.setattr(
        "build_continuation_frame",
        h2m.getattr("h2_build_continuation_frame")?,
    )?;
    h2m.setattr("build_data_frame", h2m.getattr("h2_build_data_frame")?)?;
    h2m.setattr(
        "build_window_update_frame",
        h2m.getattr("h2_build_window_update_frame")?,
    )?;
    h2m.setattr("build_ping_frame", h2m.getattr("h2_build_ping_frame")?)?;
    h2m.setattr(
        "build_rst_stream_frame",
        h2m.getattr("h2_build_rst_stream_frame")?,
    )?;
    h2m.setattr("build_goaway_frame", h2m.getattr("h2_build_goaway_frame")?)?;
    h2m.setattr(
        "build_priority_frame",
        h2m.getattr("h2_build_priority_frame")?,
    )?;
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
    m.add_class::<PyBatchResultIterator>()?;
    m.add_class::<PyCertInfo>()?;
    m.add_class::<PyResponseHash>()?;
    m.add_class::<PyRedirectHop>()?;
    m.add_class::<PyHeaders>()?;
    m.add_class::<PyRequest>()?;
    m.add_class::<PyRawConnection>()?;
    m.add("HTTPStatusError", m.py().get_type::<HTTPStatusError>())?;
    register_h2_submodule(m)?;
    crate::mock::register_mock_submodule(m)?;
    register_headers_as_mapping(m)?;
    Ok(())
}

/// Register `Headers` with `collections.abc.MutableMapping` so
/// `isinstance(h, MutableMapping)` is True. Without this, third-party
/// libraries that special-case mappings (DeepDiff, dataclasses, etc.)
/// don't recognize Headers as dict-like even though it implements the
/// full protocol. Called once at module import.
fn register_headers_as_mapping(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    let abc = py.import("collections.abc")?;
    let mutable_mapping = abc.getattr("MutableMapping")?;
    let headers_cls = m.getattr("Headers")?;
    mutable_mapping.call_method1("register", (headers_cls,))?;
    Ok(())
}
