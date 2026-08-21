// Test-fixture mock for the blasthttp Python API. Exposed as the
// `blasthttp.mock` submodule. Drop-in compatible with `BlastHTTP` so
// callers can pass it anywhere a real client is accepted; matches the
// behavior of the previous `bbot.test.mock_blasthttp.BlasthttpMock` so
// existing bbot-style tests work unmodified after migration.
//
// Design notes:
// - Handlers are matched FIFO. A consumed handler is moved to a
//   recycle queue so subsequent requests can re-match it.
// - URL matching: `str` (exact) or `re.Pattern` (call `.search` back
//   into Python). Method matching is case-insensitive.
// - Callbacks may be sync or async; coroutines returned from a sync
//   call are awaited via `pyo3_async_runtimes::tokio::into_future`.
// - The mock stays generic — bbot-specific kwarg translation
//   (auth tuple → header, cookies dict → header, raise_error, etc.)
//   is the consumer's responsibility, not ours.

use crate::python::PyResponse;
use crate::response::Response;
use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3_async_runtimes::tokio::future_into_py;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

// ── TimeoutException ──────────────────────────────────────────────

pyo3::create_exception!(
    blasthttp,
    TimeoutException,
    pyo3::exceptions::PyException,
    "Raise from a mock callback to simulate a request timeout."
);

// ── MockRequest (passed to callbacks) ─────────────────────────────

/// Read-only request snapshot delivered to mock callbacks.
#[pyclass(name = "MockRequest")]
pub struct PyMockRequest {
    #[pyo3(get)]
    url: String,
    #[pyo3(get)]
    method: String,
    headers: Py<PyDict>,
    content: Py<PyBytes>,
}

#[pymethods]
impl PyMockRequest {
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> Py<PyDict> {
        self.headers.clone_ref(py)
    }

    #[getter]
    fn content<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        self.content.clone_ref(py)
    }

    fn __repr__(&self) -> String {
        format!("MockRequest(method='{}', url='{}')", self.method, self.url)
    }
}

// ── MockResponse (returned from callbacks) ────────────────────────

/// Declarative mock response. Returned from a callback to describe
/// what the mock should reply with.
#[pyclass(name = "MockResponse")]
pub struct PyMockResponse {
    #[pyo3(get, set)]
    status_code: u16,
    #[pyo3(get, set)]
    text: String,
    /// Stored as a Python object so callers can pass either a dict or
    /// a list of tuples (when duplicate names matter).
    headers: Py<PyAny>,
}

#[pymethods]
impl PyMockResponse {
    #[new]
    #[pyo3(signature = (status_code=200, json=None, text=None, headers=None))]
    fn new<'py>(
        py: Python<'py>,
        status_code: u16,
        json: Option<Bound<'py, PyAny>>,
        text: Option<String>,
        headers: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        // text > json > empty
        let text = if let Some(t) = text {
            t
        } else if let Some(j) = json {
            py.import("json")?
                .call_method1("dumps", (j,))?
                .extract::<String>()?
        } else {
            String::new()
        };
        let headers = match headers {
            Some(h) => h.unbind(),
            None => PyDict::new(py).into_any().unbind(),
        };
        Ok(PyMockResponse {
            status_code,
            text,
            headers,
        })
    }

    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> Py<PyAny> {
        self.headers.clone_ref(py)
    }

    #[setter(headers)]
    fn set_headers(&mut self, value: Py<PyAny>) {
        self.headers = value;
    }

    fn __repr__(&self) -> String {
        format!("MockResponse(status_code={})", self.status_code)
    }
}

// ── Handler representation ────────────────────────────────────────
//
// `Py<PyAny>` does not impl `Clone` (cloning a Python ref needs the
// GIL), so Handler / HandlerKind get manual `clone_with_gil` helpers
// instead of a derive.

enum HandlerKind {
    Response {
        status_code: u16,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
        match_headers: Option<Py<PyDict>>,
        match_json: Option<Py<PyDict>>,
    },
    Callback {
        callback: Py<PyAny>,
    },
}

impl HandlerKind {
    fn clone_with_gil(&self, py: Python<'_>) -> Self {
        match self {
            HandlerKind::Response {
                status_code,
                body,
                headers,
                match_headers,
                match_json,
            } => HandlerKind::Response {
                status_code: *status_code,
                body: body.clone(),
                headers: headers.clone(),
                match_headers: match_headers.as_ref().map(|p| p.clone_ref(py)),
                match_json: match_json.as_ref().map(|p| p.clone_ref(py)),
            },
            HandlerKind::Callback { callback } => HandlerKind::Callback {
                callback: callback.clone_ref(py),
            },
        }
    }
}

struct Handler {
    /// `Some(re.Pattern | str)` for filtered matching, `None` for any URL.
    url: Option<Py<PyAny>>,
    /// Optional case-insensitive method filter.
    method: Option<String>,
    kind: HandlerKind,
}

impl Handler {
    fn clone_with_gil(&self, py: Python<'_>) -> Self {
        Handler {
            url: self.url.as_ref().map(|p| p.clone_ref(py)),
            method: self.method.clone(),
            kind: self.kind.clone_with_gil(py),
        }
    }
}

struct MockState {
    handlers: Vec<Handler>,
    recycled: Vec<Handler>,
}

// ── Helpers ───────────────────────────────────────────────────────

/// Coerce a Python headers value (dict, list of tuples, or None) into
/// a Vec<(String, String)>. List values inside a dict expand into
/// multiple tuples (e.g. multiple `Set-Cookie`).
fn normalize_headers(headers: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<(String, String)>> {
    let Some(h) = headers else {
        return Ok(Vec::new());
    };
    if let Ok(d) = h.cast::<PyDict>() {
        let mut out = Vec::with_capacity(d.len());
        for (k, v) in d.iter() {
            let k_str: String = k.extract()?;
            if let Ok(list) = v.cast::<PyList>() {
                for item in list.iter() {
                    out.push((k_str.clone(), item.extract::<String>()?));
                }
            } else {
                out.push((k_str, v.extract::<String>()?));
            }
        }
        Ok(out)
    } else if let Ok(list) = h.cast::<PyList>() {
        let mut out = Vec::with_capacity(list.len());
        for entry in list.iter() {
            let tup: (String, String) = entry.extract()?;
            out.push(tup);
        }
        Ok(out)
    } else {
        Err(PyTypeError::new_err(
            "headers must be a dict, list of (name, value) tuples, or None",
        ))
    }
}

/// Match a URL against `str` (exact) or `re.Pattern` (call `.search`).
fn url_matches(py: Python<'_>, pattern: Option<&Py<PyAny>>, url: &str) -> PyResult<bool> {
    let Some(pat) = pattern else {
        return Ok(true);
    };
    let bound = pat.bind(py);
    if let Ok(s) = bound.extract::<&str>() {
        return Ok(s == url);
    }
    let result = bound.call_method1("search", (url,))?;
    result.is_truthy()
}

fn body_from_arg(body: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<u8>> {
    let Some(b) = body else {
        return Ok(Vec::new());
    };
    if b.is_none() {
        return Ok(Vec::new());
    }
    if let Ok(s) = b.extract::<String>() {
        return Ok(s.into_bytes());
    }
    if let Ok(bs) = b.extract::<Vec<u8>>() {
        return Ok(bs);
    }
    Err(PyTypeError::new_err("body must be str, bytes, or None"))
}

fn ensure_content_type(headers: &mut Vec<(String, String)>, default: &str) {
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        headers.push(("Content-Type".to_string(), default.to_string()));
    }
}

fn make_response(
    url: String,
    method: String,
    status_code: u16,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
) -> Response {
    Response {
        url: url.clone(),
        status: status_code,
        headers,
        body_bytes: body,
        elapsed_ms: 0,
        redirect_chain: Vec::new(),
        cert_info: None,
        peer_ip: None,
        request_url: url,
        request_method: method,
        debug_log: Vec::new(),
        decode_error: None,
        body_cache: OnceLock::new(),
        raw_headers_cache: OnceLock::new(),
        cookies_cache: OnceLock::new(),
        hash_cache: OnceLock::new(),
    }
}

fn header_subset_match(
    py: Python<'_>,
    expected: &Py<PyDict>,
    req_headers: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let exp = expected.bind(py);
    for (k, v) in exp.iter() {
        let key_str: String = k.extract()?;
        match req_headers.get_item(&key_str)? {
            Some(actual) => {
                if !actual.eq(&v)? {
                    return Ok(false);
                }
            }
            None => return Ok(false),
        }
    }
    Ok(true)
}

fn json_subset_match(py: Python<'_>, expected: &Py<PyDict>, body: &[u8]) -> PyResult<bool> {
    if body.is_empty() {
        return Ok(expected.bind(py).is_empty());
    }
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let parsed = match py.import("json")?.call_method1("loads", (body_str,)) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let parsed_dict = match parsed.cast::<PyDict>() {
        Ok(d) => d,
        Err(_) => return Ok(false),
    };
    for (k, v) in expected.bind(py).iter() {
        let key_str: String = k.extract()?;
        match parsed_dict.get_item(&key_str)? {
            Some(actual) => {
                if !actual.eq(&v)? {
                    return Ok(false);
                }
            }
            None => return Ok(false),
        }
    }
    Ok(true)
}

fn poisoned<E>(_: E) -> PyErr {
    PyRuntimeError::new_err("BlasthttpMock state lock poisoned")
}

/// Sync handler-pick. Holds the lock just long enough to find a match,
/// remove it from `handlers` (or peek it from `recycled`), and clone.
/// Returns `None` if no handler matches.
fn pick_handler(
    py: Python<'_>,
    state: &Mutex<MockState>,
    url: &str,
    method: &str,
    req_headers_dict: &Bound<'_, PyDict>,
    body: &[u8],
) -> PyResult<Option<Handler>> {
    let mut guard = state.lock().map_err(poisoned)?;

    // Two passes: primary first, then recycled.
    for primary in [true, false] {
        let list = if primary {
            &guard.handlers
        } else {
            &guard.recycled
        };
        let mut chosen_idx: Option<usize> = None;
        for (i, h) in list.iter().enumerate() {
            if !url_matches(py, h.url.as_ref(), url)? {
                continue;
            }
            if let Some(ref m) = h.method
                && !m.eq_ignore_ascii_case(method)
            {
                continue;
            }
            if let HandlerKind::Response {
                match_headers,
                match_json,
                ..
            } = &h.kind
            {
                if let Some(mh) = match_headers
                    && !header_subset_match(py, mh, req_headers_dict)?
                {
                    continue;
                }
                if let Some(mj) = match_json
                    && !json_subset_match(py, mj, body)?
                {
                    continue;
                }
            }
            chosen_idx = Some(i);
            break;
        }
        if let Some(i) = chosen_idx {
            return if primary {
                let h = guard.handlers.remove(i);
                let recycled_copy = h.clone_with_gil(py);
                guard.recycled.push(recycled_copy);
                Ok(Some(h))
            } else {
                Ok(Some(guard.recycled[i].clone_with_gil(py)))
            };
        }
    }
    Ok(None)
}

/// Sync part of dispatch: pick a handler and (for response handlers)
/// build the Response. For callback handlers, returns the callback
/// PyObject and a built MockRequest so the async caller can invoke
/// + await.
enum DispatchPlan {
    // Boxed to keep the enum size bounded — `Response` is ~600 bytes
    // and lives only briefly here before being unwrapped.
    Response(Box<Response>),
    Callback {
        callback: Py<PyAny>,
        mock_request: Py<PyMockRequest>,
    },
}

fn plan_dispatch(
    py: Python<'_>,
    state: &Mutex<MockState>,
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> PyResult<DispatchPlan> {
    // Build a one-shot dict for predicate checks.
    let req_headers_dict = PyDict::new(py);
    for (k, v) in headers {
        req_headers_dict.set_item(k, v)?;
    }

    let Some(handler) = pick_handler(py, state, url, method, &req_headers_dict, body)? else {
        return Err(PyRuntimeError::new_err(format!(
            "No mock response registered for {} {}",
            method, url
        )));
    };

    match handler.kind {
        HandlerKind::Response {
            status_code,
            body: resp_body,
            headers: resp_headers,
            ..
        } => Ok(DispatchPlan::Response(Box::new(make_response(
            url.to_string(),
            method.to_string(),
            status_code,
            resp_body,
            resp_headers,
        )))),
        HandlerKind::Callback { callback } => {
            let mock_req = PyMockRequest {
                url: url.to_string(),
                method: method.to_string(),
                headers: req_headers_dict.unbind(),
                content: PyBytes::new(py, body).unbind(),
            };
            Ok(DispatchPlan::Callback {
                callback,
                mock_request: Py::new(py, mock_req)?,
            })
        }
    }
}

/// Convert the result of a callback (sync or post-await) into a Response.
fn callback_result_to_response(
    py: Python<'_>,
    result: &Bound<'_, PyAny>,
    url: &str,
    method: &str,
) -> PyResult<Response> {
    if let Ok(mr_ref) = result.cast::<PyMockResponse>() {
        let mr = mr_ref.borrow();
        let mut header_list = normalize_headers(Some(&mr.headers.clone_ref(py).into_bound(py)))?;
        ensure_content_type(&mut header_list, "text/plain; charset=utf-8");
        Ok(make_response(
            url.to_string(),
            method.to_string(),
            mr.status_code,
            mr.text.clone().into_bytes(),
            header_list,
        ))
    } else if let Ok(pr_ref) = result.cast::<PyResponse>() {
        Ok(pr_ref.borrow().inner.clone())
    } else {
        Err(PyTypeError::new_err(
            "callback must return MockResponse or blasthttp.Response",
        ))
    }
}

/// Full async dispatch: pick handler, invoke (await if coroutine),
/// convert to Response.
async fn dispatch_one(
    state: Arc<Mutex<MockState>>,
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> PyResult<Response> {
    // Plan synchronously.
    let plan = Python::attach(|py| plan_dispatch(py, &state, &url, &method, &headers, &body))?;

    match plan {
        DispatchPlan::Response(resp) => Ok(*resp),
        DispatchPlan::Callback {
            callback,
            mock_request,
        } => {
            // Call the callback. If it returns a coroutine, await it.
            let (result_obj, is_coro) = Python::attach(|py| -> PyResult<(Py<PyAny>, bool)> {
                let result = callback.bind(py).call1((mock_request,))?;
                let inspect = py.import("inspect")?;
                let is_coro: bool = inspect.call_method1("iscoroutine", (&result,))?.extract()?;
                Ok((result.unbind(), is_coro))
            })?;

            let final_obj = if is_coro {
                let fut = Python::attach(|py| {
                    pyo3_async_runtimes::tokio::into_future(result_obj.bind(py).clone())
                })?;
                fut.await?
            } else {
                result_obj
            };

            Python::attach(|py| callback_result_to_response(py, final_obj.bind(py), &url, &method))
        }
    }
}

// ── BlasthttpMock pyclass ─────────────────────────────────────────

/// Mock fixture compatible with `blasthttp.BlastHTTP`. Register
/// responses with `add_response()` or callbacks with `add_callback()`,
/// then dispatch through `request()` / `request_batch_stream()` as
/// you would with a real client.
///
/// Pass-through: when constructed with a `real_client` argument,
/// requests whose URLs return False from the optional `should_mock_fn`
/// predicate are forwarded to the real client.
#[pyclass(name = "BlasthttpMock")]
pub struct PyBlasthttpMock {
    state: Arc<Mutex<MockState>>,
    real_client: Option<Py<PyAny>>,
    should_mock_fn: Option<Py<PyAny>>,
}

#[pymethods]
impl PyBlasthttpMock {
    #[new]
    #[pyo3(signature = (real_client=None, should_mock_fn=None))]
    fn new(real_client: Option<Py<PyAny>>, should_mock_fn: Option<Py<PyAny>>) -> Self {
        PyBlasthttpMock {
            state: Arc::new(Mutex::new(MockState {
                handlers: Vec::new(),
                recycled: Vec::new(),
            })),
            real_client,
            should_mock_fn,
        }
    }

    /// Register a static mock response. Matches FIFO; once consumed,
    /// the response is recycled so subsequent matches can reuse it.
    #[pyo3(signature = (
        url=None,
        method=None,
        text=None,
        json=None,
        content=None,
        status_code=200,
        headers=None,
        match_headers=None,
        match_json=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn add_response(
        &self,
        py: Python<'_>,
        url: Option<Py<PyAny>>,
        method: Option<String>,
        text: Option<String>,
        json: Option<Bound<'_, PyAny>>,
        content: Option<Bound<'_, PyAny>>,
        status_code: u16,
        headers: Option<Bound<'_, PyAny>>,
        match_headers: Option<Py<PyDict>>,
        match_json: Option<Py<PyDict>>,
    ) -> PyResult<()> {
        let mut header_list = normalize_headers(headers.as_ref())?;

        let body: Vec<u8> = if let Some(t) = text {
            ensure_content_type(&mut header_list, "text/plain; charset=utf-8");
            t.into_bytes()
        } else if let Some(j) = json {
            let s: String = py.import("json")?.call_method1("dumps", (j,))?.extract()?;
            ensure_content_type(&mut header_list, "application/json");
            s.into_bytes()
        } else if let Some(c) = content {
            ensure_content_type(&mut header_list, "application/octet-stream");
            // Try bytes first so binary content round-trips without UTF-8 decode.
            if let Ok(bs) = c.extract::<Vec<u8>>() {
                bs
            } else if let Ok(s) = c.extract::<String>() {
                s.into_bytes()
            } else {
                return Err(PyTypeError::new_err("content must be bytes or str"));
            }
        } else {
            Vec::new()
        };

        let handler = Handler {
            url,
            method,
            kind: HandlerKind::Response {
                status_code,
                body,
                headers: header_list,
                match_headers,
                match_json,
            },
        };
        self.state.lock().map_err(poisoned)?.handlers.push(handler);
        Ok(())
    }

    /// Register a callback. The callback receives a `MockRequest` and
    /// is expected to return a `MockResponse` or a `blasthttp.Response`.
    /// Sync and async callbacks are both supported.
    #[pyo3(signature = (callback, url=None))]
    fn add_callback(&self, callback: Py<PyAny>, url: Option<Py<PyAny>>) -> PyResult<()> {
        let handler = Handler {
            url,
            method: None,
            kind: HandlerKind::Callback { callback },
        };
        self.state.lock().map_err(poisoned)?.handlers.push(handler);
        Ok(())
    }

    /// Returns True if the URL would be intercepted (subject to
    /// `should_mock_fn`). When no predicate is set, all URLs are
    /// intercepted.
    fn should_intercept(&self, py: Python<'_>, url: &str) -> PyResult<bool> {
        let Some(ref f) = self.should_mock_fn else {
            return Ok(true);
        };
        let parsed = py
            .import("urllib.parse")?
            .call_method1("urlparse", (url,))?;
        let host: String = parsed
            .getattr("hostname")?
            .extract::<Option<String>>()?
            .unwrap_or_default();
        f.bind(py).call1((host,))?.is_truthy()
    }

    /// Dispatch a single request through the mock. Mirrors the
    /// `BlastHTTP.request` shape — most kwargs (timeout, verify_certs,
    /// retries, etc.) are accepted but ignored, since they don't apply
    /// to a mock.
    #[pyo3(signature = (
        url,
        method=None,
        headers=None,
        body=None,
        files=None,
        follow_redirects=None,
        max_redirects=None,
        **_kwargs,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn request<'py>(
        &self,
        py: Python<'py>,
        url: String,
        method: Option<String>,
        headers: Option<Bound<'py, PyAny>>,
        body: Option<Bound<'py, PyAny>>,
        files: Option<Bound<'py, PyAny>>,
        follow_redirects: Option<bool>,
        max_redirects: Option<u32>,
        _kwargs: Option<Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if !self.should_intercept(py, &url)? {
            return self.delegate_request(
                py,
                url,
                method,
                headers,
                body,
                files,
                follow_redirects,
                max_redirects,
            );
        }

        crate::python::reject_body_with_files(&body, &files)?;

        let method_str = method.unwrap_or_else(|| "GET".to_string());
        let mut header_list = normalize_headers(headers.as_ref())?;
        let body_bytes = if let Some(ref f) = files
            && !f.is_none()
        {
            let (boundary, mp_body) = crate::multipart::build_multipart(f)?;
            ensure_content_type(
                &mut header_list,
                &format!("multipart/form-data; boundary={}", boundary),
            );
            mp_body
        } else {
            body_from_arg(body.as_ref())?
        };

        let state_arc = Arc::clone(&self.state);
        let follow = follow_redirects.unwrap_or(false);
        let max_hops = max_redirects.unwrap_or(10);

        future_into_py(py, async move {
            let mut current_url = url;
            let mut hops = 0u32;
            loop {
                let response = dispatch_one(
                    Arc::clone(&state_arc),
                    current_url.clone(),
                    method_str.clone(),
                    header_list.clone(),
                    body_bytes.clone(),
                )
                .await?;

                if !follow {
                    return Python::attach(|py| {
                        Ok::<Py<PyAny>, PyErr>(
                            Bound::new(py, PyResponse::wrap(response))?
                                .into_any()
                                .unbind(),
                        )
                    });
                }

                // Check for a redirect Location header.
                let next_url: Option<String> = {
                    let status = response.status;
                    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                        None
                    } else {
                        let mut location: Option<String> = None;
                        for (k, v) in &response.headers {
                            if k.eq_ignore_ascii_case("location") {
                                location = Some(v.clone());
                                break;
                            }
                        }
                        location.map(|loc| {
                            if loc.starts_with('/') {
                                let url_to_parse = current_url.clone();
                                Python::attach(|py| -> PyResult<String> {
                                    let parsed = py
                                        .import("urllib.parse")?
                                        .call_method1("urlparse", (url_to_parse,))?;
                                    let scheme: String = parsed.getattr("scheme")?.extract()?;
                                    let netloc: String = parsed.getattr("netloc")?.extract()?;
                                    Ok(format!("{}://{}{}", scheme, netloc, loc))
                                })
                                .unwrap_or(loc)
                            } else {
                                loc
                            }
                        })
                    }
                };

                match next_url {
                    None => {
                        return Python::attach(|py| {
                            Ok::<Py<PyAny>, PyErr>(
                                Bound::new(py, PyResponse::wrap(response))?
                                    .into_any()
                                    .unbind(),
                            )
                        });
                    }
                    Some(loc) => {
                        hops += 1;
                        if hops > max_hops {
                            return Err(PyRuntimeError::new_err(format!(
                                "exceeded {} redirects starting from mock dispatch",
                                max_hops
                            )));
                        }
                        current_url = loc;
                    }
                }
            }
        })
    }

    /// Streaming batch — yields `BatchResult` objects one at a time.
    /// Mock results stream first (in input order), then passthrough
    /// results follow (in completion order from the real client).
    #[pyo3(signature = (configs, concurrency=50, rate_limit=None))]
    fn request_batch_stream(
        &self,
        py: Python<'_>,
        configs: Vec<Py<PyAny>>,
        concurrency: usize,
        rate_limit: Option<f64>,
    ) -> PyResult<PyMockBatchIterator> {
        // Split into mock-bound and passthrough configs.
        let mut mock_entries: Vec<MockBatchEntry> = Vec::new();
        let mut passthrough_configs: Vec<Py<PyAny>> = Vec::new();

        for cfg in configs {
            let bound = cfg.bind(py);
            let url: String = bound.getattr("url")?.extract()?;
            if self.should_intercept(py, &url)? {
                let method: String = bound
                    .getattr("method")?
                    .extract::<Option<String>>()?
                    .unwrap_or_else(|| "GET".to_string());
                let headers: Option<Vec<(String, String)>> = bound.getattr("headers")?.extract()?;
                let body_obj = bound.getattr("body")?;
                let body = if body_obj.is_none() {
                    None
                } else {
                    Some(body_obj)
                };
                let files_obj = bound.getattr("files").ok();
                let files = files_obj.filter(|f| !f.is_none());
                let (body_bytes, final_headers) =
                    crate::python::apply_body_and_files(body, files, headers)?;
                mock_entries.push(MockBatchEntry {
                    url,
                    method,
                    headers: final_headers.unwrap_or_default(),
                    body: body_bytes.unwrap_or_default(),
                });
            } else {
                passthrough_configs.push(cfg);
            }
        }

        // Open passthrough stream now (lazily — no awaits) if needed.
        let passthrough_iter: Option<Py<PyAny>> =
            if let (Some(client), false) = (&self.real_client, passthrough_configs.is_empty()) {
                let kwargs = PyDict::new(py);
                kwargs.set_item("concurrency", concurrency)?;
                if let Some(rl) = rate_limit {
                    kwargs.set_item("rate_limit", rl)?;
                }
                let stream = client.bind(py).call_method(
                    "request_batch_stream",
                    (passthrough_configs,),
                    Some(&kwargs),
                )?;
                let aiter = stream.call_method0("__aiter__")?;
                Some(aiter.unbind())
            } else {
                None
            };

        Ok(PyMockBatchIterator {
            state: Arc::new(Mutex::new(MockBatchIterState {
                pending_mocks: VecDeque::from(mock_entries),
                passthrough_iter,
                buffered: VecDeque::new(),
                exhausted: false,
            })),
            mock_state: Arc::clone(&self.state),
        })
    }

    /// Convenience non-streaming batch. Drains the stream and returns
    /// a `list[BatchResult]`.
    #[pyo3(signature = (configs, concurrency=50, rate_limit=None))]
    fn request_batch<'py>(
        slf: PyRef<'py, Self>,
        configs: Vec<Py<PyAny>>,
        concurrency: usize,
        rate_limit: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let py = slf.py();
        let iterator = slf.request_batch_stream(py, configs, concurrency, rate_limit)?;
        let iter_obj: Py<PyAny> = Bound::new(py, iterator)?.into_any().unbind();

        future_into_py(py, async move {
            let mut out: Vec<Py<PyAny>> = Vec::new();
            loop {
                // Each iteration: call __anext__ to get an awaitable, then await.
                let awaitable = match Python::attach(|py| -> PyResult<Py<PyAny>> {
                    iter_obj
                        .bind(py)
                        .call_method0("__anext__")
                        .map(|b| b.unbind())
                }) {
                    Ok(a) => a,
                    Err(e) => {
                        let is_stop =
                            Python::attach(|py| e.is_instance_of::<PyStopAsyncIteration>(py));
                        if is_stop {
                            break;
                        }
                        return Err(e);
                    }
                };
                let fut = Python::attach(|py| {
                    pyo3_async_runtimes::tokio::into_future(awaitable.bind(py).clone())
                })?;
                match fut.await {
                    Ok(v) => out.push(v),
                    Err(e) => {
                        let is_stop =
                            Python::attach(|py| e.is_instance_of::<PyStopAsyncIteration>(py));
                        if is_stop {
                            break;
                        }
                        return Err(e);
                    }
                }
            }
            Ok(out)
        })
    }
}

impl PyBlasthttpMock {
    /// Forward `request` to the configured real client when the URL
    /// is excluded from the mock.
    #[allow(clippy::too_many_arguments)]
    fn delegate_request<'py>(
        &self,
        py: Python<'py>,
        url: String,
        method: Option<String>,
        headers: Option<Bound<'py, PyAny>>,
        body: Option<Bound<'py, PyAny>>,
        files: Option<Bound<'py, PyAny>>,
        follow_redirects: Option<bool>,
        max_redirects: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let Some(ref client) = self.real_client else {
            return Err(PyRuntimeError::new_err(format!(
                "URL {url} is excluded by should_mock_fn but no real_client was provided",
            )));
        };
        let kwargs = PyDict::new(py);
        if let Some(m) = method {
            kwargs.set_item("method", m)?;
        }
        if let Some(h) = headers {
            kwargs.set_item("headers", h)?;
        }
        if let Some(b) = body {
            kwargs.set_item("body", b)?;
        }
        if let Some(f) = files {
            kwargs.set_item("files", f)?;
        }
        if let Some(f) = follow_redirects {
            kwargs.set_item("follow_redirects", f)?;
        }
        if let Some(mr) = max_redirects {
            kwargs.set_item("max_redirects", mr)?;
        }
        client
            .bind(py)
            .call_method("request", (url,), Some(&kwargs))
    }
}

#[derive(Clone)]
struct MockBatchEntry {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

// ── Streaming batch iterator ──────────────────────────────────────

struct MockBatchIterState {
    pending_mocks: VecDeque<MockBatchEntry>,
    passthrough_iter: Option<Py<PyAny>>,
    /// Buffered BatchResults from a passthrough chunk that yielded a
    /// list. Drained one at a time.
    buffered: VecDeque<Py<PyAny>>,
    exhausted: bool,
}

#[pyclass(name = "MockBatchIterator")]
pub struct PyMockBatchIterator {
    state: Arc<Mutex<MockBatchIterState>>,
    /// Reference to the parent mock's handler queue, for dispatching
    /// the pending_mocks entries.
    mock_state: Arc<Mutex<MockState>>,
}

#[pymethods]
impl PyMockBatchIterator {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let state = Arc::clone(&self.state);
        let mock_state = Arc::clone(&self.mock_state);

        future_into_py(py, async move {
            loop {
                // 1. If we have buffered passthrough items, drain those first.
                let buffered_item = {
                    let mut g = state.lock().map_err(poisoned)?;
                    g.buffered.pop_front()
                };
                if let Some(item) = buffered_item {
                    return Ok(item);
                }

                // 2. If we have pending mock entries, dispatch one synchronously.
                let mock_entry = {
                    let mut g = state.lock().map_err(poisoned)?;
                    g.pending_mocks.pop_front()
                };
                if let Some(entry) = mock_entry {
                    let resp_or_err = dispatch_one(
                        Arc::clone(&mock_state),
                        entry.url.clone(),
                        entry.method,
                        entry.headers,
                        entry.body,
                    )
                    .await;
                    return Python::attach(|py| -> PyResult<Py<PyAny>> {
                        match resp_or_err {
                            Ok(resp) => batch_result_obj(py, &entry.url, Some(resp), None),
                            Err(e) => batch_result_obj(py, &entry.url, None, Some(e.to_string())),
                        }
                    });
                }

                // 3. Otherwise pull from the passthrough stream.
                let iter_clone = Python::attach(|py| -> PyResult<Option<Py<PyAny>>> {
                    let g = state.lock().map_err(poisoned)?;
                    if g.exhausted {
                        return Ok(None);
                    }
                    Ok(g.passthrough_iter.as_ref().map(|i| i.clone_ref(py)))
                })?;
                let Some(iter_clone) = iter_clone else {
                    let mut g = state.lock().map_err(poisoned)?;
                    g.exhausted = true;
                    return Err(PyStopAsyncIteration::new_err("end of stream"));
                };

                let coro = Python::attach(|py| -> PyResult<Py<PyAny>> {
                    iter_clone
                        .bind(py)
                        .call_method0("__anext__")
                        .map(|b| b.unbind())
                })?;
                let fut = Python::attach(|py| {
                    pyo3_async_runtimes::tokio::into_future(coro.bind(py).clone())
                })?;
                let value = match fut.await {
                    Ok(v) => v,
                    Err(e) => {
                        let is_stop =
                            Python::attach(|py| e.is_instance_of::<PyStopAsyncIteration>(py));
                        if is_stop {
                            let mut g = state.lock().map_err(poisoned)?;
                            g.exhausted = true;
                            return Err(PyStopAsyncIteration::new_err("end of stream"));
                        }
                        return Err(e);
                    }
                };

                // The native iterator yields lists; flatten them.
                let mut to_buffer: Vec<Py<PyAny>> = Vec::new();
                let single = Python::attach(|py| -> PyResult<Option<Py<PyAny>>> {
                    let bound = value.bind(py);
                    if let Ok(list) = bound.cast::<PyList>() {
                        for item in list.iter() {
                            to_buffer.push(item.unbind());
                        }
                        Ok(None)
                    } else {
                        Ok(Some(value.clone_ref(py)))
                    }
                })?;
                if let Some(s) = single {
                    return Ok(s);
                }
                if to_buffer.is_empty() {
                    // Empty list — keep pulling.
                    continue;
                }
                let first = to_buffer.remove(0);
                {
                    let mut g = state.lock().map_err(poisoned)?;
                    g.buffered.extend(to_buffer);
                }
                return Ok(first);
            }
        })
    }
}

/// Build a `blasthttp.BatchResult` Python object wrapping our Response.
fn batch_result_obj(
    py: Python<'_>,
    url: &str,
    response: Option<Response>,
    error: Option<String>,
) -> PyResult<Py<PyAny>> {
    let cls = py.import("blasthttp")?.getattr("BatchResult")?;
    let kwargs = PyDict::new(py);
    if let Some(r) = response {
        let py_resp = Bound::new(py, PyResponse::wrap(r))?;
        kwargs.set_item("response", py_resp)?;
    }
    if let Some(e) = error {
        kwargs.set_item("error", e)?;
    }
    Ok(cls.call((url,), Some(&kwargs))?.unbind())
}

// ── Submodule registration ────────────────────────────────────────

pub fn register_mock_submodule<'py>(parent: &Bound<'py, PyModule>) -> PyResult<()> {
    let py = parent.py();
    let m = PyModule::new(py, "mock")?;
    m.add_class::<PyBlasthttpMock>()?;
    m.add_class::<PyMockRequest>()?;
    m.add_class::<PyMockResponse>()?;
    m.add_class::<PyMockBatchIterator>()?;
    m.add("TimeoutException", py.get_type::<TimeoutException>())?;
    parent.add("mock", &m)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("blasthttp.mock", m)?;
    Ok(())
}
