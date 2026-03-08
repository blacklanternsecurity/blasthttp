"""Comprehensive tests for blasthttp Python bindings.

Tests native PyO3 classes, attribute access, batch error handling,
type correctness, and edge cases.

Run: .venv/bin/python test_python_bindings.py
"""
import blasthttp
import traceback
import sys


passed = 0
failed = 0
errors = []


def test(name):
    """Decorator to register and run a test."""
    def decorator(fn):
        global passed, failed
        try:
            fn()
            passed += 1
            print(f"  PASS  {name}")
        except Exception as e:
            failed += 1
            tb = traceback.format_exc()
            errors.append((name, tb))
            print(f"  FAIL  {name}: {e}")
        return fn
    return decorator


# ── Module-level checks ───────────────────────────────────────────

@test("module exports BlastHTTP class")
def _():
    assert hasattr(blasthttp, "BlastHTTP")

@test("module exports BatchConfig class")
def _():
    assert hasattr(blasthttp, "BatchConfig")

@test("module exports Response class")
def _():
    assert hasattr(blasthttp, "Response")

@test("module exports BatchResult class")
def _():
    assert hasattr(blasthttp, "BatchResult")

@test("module exports CertInfo class")
def _():
    assert hasattr(blasthttp, "CertInfo")

@test("module exports ResponseHash class")
def _():
    assert hasattr(blasthttp, "ResponseHash")

@test("module exports RedirectHop class")
def _():
    assert hasattr(blasthttp, "RedirectHop")


# ── Client creation ───────────────────────────────────────────────

@test("BlastHTTP() creates a client")
def _():
    client = blasthttp.BlastHTTP()
    assert client is not None


# ── Single request: response type and attributes ──────────────────

client = blasthttp.BlastHTTP()

@test("request() returns Response object")
def _():
    r = client.request("https://example.com")
    assert isinstance(r, blasthttp.Response)

@test("response.status is an int")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.status, int)
    assert r.status == 200

@test("response.url is a string")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.url, str)
    assert "example.com" in r.url

@test("response.body is a string")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.body, str)
    assert len(r.body) > 0

@test("response.body_bytes is bytes")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.body_bytes, bytes)
    assert len(r.body_bytes) > 0

@test("response.body and body_bytes are consistent")
def _():
    r = client.request("https://example.com")
    assert r.body == r.body_bytes.decode("utf-8")

@test("response.elapsed_ms is a positive int")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.elapsed_ms, int)
    assert r.elapsed_ms > 0

@test("response.headers is a list of tuples")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.headers, list)
    assert len(r.headers) > 0
    for name, value in r.headers:
        assert isinstance(name, str)
        assert isinstance(value, str)

@test("response.redirect_chain is a list (empty when not following)")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.redirect_chain, list)


# ── Response repr ─────────────────────────────────────────────────

@test("response has useful repr")
def _():
    r = client.request("https://example.com")
    s = repr(r)
    assert "Response(" in s
    assert "example.com" in s
    assert "200" in s


# ── Hash attributes ───────────────────────────────────────────────

@test("response.hash is a ResponseHash object")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.hash, blasthttp.ResponseHash)

@test("hash.body_md5 is a 32-char hex string")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.hash.body_md5, str)
    assert len(r.hash.body_md5) == 32

@test("hash.body_sha256 is a 64-char hex string")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.hash.body_sha256, str)
    assert len(r.hash.body_sha256) == 64

@test("hash.body_mmh3 is an int")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.hash.body_mmh3, int)

@test("hash.header_md5 is a 32-char hex string")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.hash.header_md5, str)
    assert len(r.hash.header_md5) == 32

@test("hash.header_sha256 is a 64-char hex string")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.hash.header_sha256, str)
    assert len(r.hash.header_sha256) == 64

@test("hash.header_mmh3 is an int")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.hash.header_mmh3, int)

@test("hash has useful repr")
def _():
    r = client.request("https://example.com")
    s = repr(r.hash)
    assert "ResponseHash(" in s


# ── TLS cert info ─────────────────────────────────────────────────

@test("response.cert_info is a CertInfo for HTTPS")
def _():
    r = client.request("https://example.com")
    assert r.cert_info is not None
    assert isinstance(r.cert_info, blasthttp.CertInfo)

@test("cert_info.common_name is a string or None")
def _():
    r = client.request("https://example.com")
    cn = r.cert_info.common_name
    assert cn is None or isinstance(cn, str)

@test("cert_info.sans is a list of strings")
def _():
    r = client.request("https://example.com")
    sans = r.cert_info.sans
    assert isinstance(sans, list)
    # example.com should have SANs
    assert len(sans) > 0
    for s in sans:
        assert isinstance(s, str)

@test("cert_info.issuer is a string or None")
def _():
    r = client.request("https://example.com")
    assert r.cert_info.issuer is None or isinstance(r.cert_info.issuer, str)

@test("cert_info.not_before is a string")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.cert_info.not_before, str)

@test("cert_info.not_after is a string")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.cert_info.not_after, str)

@test("cert_info.fingerprint_sha256 is a hex string with colons")
def _():
    r = client.request("https://example.com")
    fp = r.cert_info.fingerprint_sha256
    assert isinstance(fp, str)
    assert ":" in fp  # colon-separated hex

@test("cert_info.emails is a list")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.cert_info.emails, list)

@test("cert_info has useful repr")
def _():
    r = client.request("https://example.com")
    s = repr(r.cert_info)
    assert "CertInfo(" in s


# ── Request options ───────────────────────────────────────────────

@test("request() accepts method kwarg")
def _():
    r = client.request("https://httpbin.org/post", method="POST")
    assert r.status == 200

@test("request() accepts headers kwarg")
def _():
    r = client.request("https://httpbin.org/headers",
                     headers=[("X-Test", "blasthttp")])
    assert r.status == 200
    assert "blasthttp" in r.body

@test("request() accepts body kwarg")
def _():
    r = client.request("https://httpbin.org/post",
                     method="POST", body="hello world")
    assert r.status == 200
    assert "hello world" in r.body

@test("request() accepts timeout kwarg")
def _():
    r = client.request("https://example.com", timeout=30)
    assert r.status == 200


# ── Error handling: single request ────────────────────────────────

@test("request() raises RuntimeError on connection failure")
def _():
    try:
        client.request("https://localhost:1")
        assert False, "should have raised"
    except RuntimeError as e:
        assert isinstance(str(e), str)
        assert len(str(e)) > 0

@test("request() raises RuntimeError on invalid URL")
def _():
    try:
        client.request("not_a_url")
        assert False, "should have raised"
    except RuntimeError:
        pass

@test("request() raises RuntimeError on timeout")
def _():
    try:
        # httpbin delay endpoint with very short timeout
        client.request("https://httpbin.org/delay/10", timeout=1)
        assert False, "should have raised"
    except RuntimeError as e:
        assert "timed out" in str(e).lower()


# ── BatchConfig ───────────────────────────────────────────────────

@test("BatchConfig() takes url positional arg")
def _():
    cfg = blasthttp.BatchConfig("https://example.com")
    assert cfg.url == "https://example.com"

@test("BatchConfig() takes all kwargs")
def _():
    cfg = blasthttp.BatchConfig(
        "https://example.com",
        method="POST",
        headers=[("Foo", "bar")],
        body="data",
        timeout=5,
        follow_redirects=True,
        max_redirects=3,
        verify_certs=False,
        proxy=None,
    )
    assert cfg.url == "https://example.com"
    assert cfg.method == "POST"
    assert cfg.headers == [("Foo", "bar")]
    assert cfg.body == "data"
    assert cfg.timeout == 5
    assert cfg.follow_redirects == True
    assert cfg.max_redirects == 3

@test("BatchConfig fields are settable")
def _():
    cfg = blasthttp.BatchConfig("https://example.com")
    cfg.method = "PUT"
    assert cfg.method == "PUT"
    cfg.url = "https://other.com"
    assert cfg.url == "https://other.com"


# ── Batch requests ────────────────────────────────────────────────

@test("request_batch() returns list of BatchResult objects")
def _():
    results = client.request_batch([
        blasthttp.BatchConfig("https://example.com"),
        blasthttp.BatchConfig("https://example.org"),
    ])
    assert isinstance(results, list)
    assert len(results) == 2
    for r in results:
        assert isinstance(r, blasthttp.BatchResult)

@test("successful batch result has response and no error")
def _():
    results = client.request_batch([
        blasthttp.BatchConfig("https://example.com"),
    ])
    r = results[0]
    assert r.success is True
    assert r.response is not None
    assert isinstance(r.response, blasthttp.Response)
    assert r.error is None
    assert r.response.status == 200

@test("batch result.url matches input")
def _():
    results = client.request_batch([
        blasthttp.BatchConfig("https://example.com"),
    ])
    assert results[0].url == "https://example.com"

@test("batch result response has all attributes")
def _():
    results = client.request_batch([
        blasthttp.BatchConfig("https://example.com"),
    ])
    resp = results[0].response
    assert isinstance(resp.status, int)
    assert isinstance(resp.url, str)
    assert isinstance(resp.body, str)
    assert isinstance(resp.headers, list)
    assert isinstance(resp.hash, blasthttp.ResponseHash)
    assert resp.cert_info is not None

@test("batch preserves per-request config")
def _():
    results = client.request_batch([
        blasthttp.BatchConfig("https://httpbin.org/post", method="POST", body="batch_test"),
    ])
    assert results[0].success
    assert "batch_test" in results[0].response.body


# ── CRITICAL: batch error handling ────────────────────────────────

@test("failed batch request returns error, not exception")
def _():
    """Errors within a batch must NOT be silently dropped.
    The Python side must be able to see which URLs failed and why."""
    results = client.request_batch([
        blasthttp.BatchConfig("https://example.com"),            # should succeed
        blasthttp.BatchConfig("https://localhost:1"),             # should fail - connection refused
        blasthttp.BatchConfig("https://example.org"),            # should succeed
    ], concurrency=10)

    assert len(results) == 3, f"expected 3 results, got {len(results)}"

    # Find the failed one
    successes = [r for r in results if r.success]
    failures = [r for r in results if not r.success]

    assert len(failures) >= 1, "expected at least 1 failure"

    for f in failures:
        assert f.response is None, "failed request should have response=None"
        assert f.error is not None, "failed request should have error message"
        assert isinstance(f.error, str)
        assert len(f.error) > 0, "error message should not be empty"
        assert f.url == "https://localhost:1"

    assert len(successes) >= 1, "expected at least 1 success"

@test("batch with ALL failures returns all errors")
def _():
    results = client.request_batch([
        blasthttp.BatchConfig("https://localhost:1"),
        blasthttp.BatchConfig("https://localhost:2"),
    ])
    assert len(results) == 2
    for r in results:
        assert not r.success
        assert r.response is None
        assert r.error is not None
        assert len(r.error) > 0

@test("batch result repr shows status or error")
def _():
    results = client.request_batch([
        blasthttp.BatchConfig("https://example.com"),
        blasthttp.BatchConfig("https://localhost:1"),
    ])
    for r in results:
        s = repr(r)
        assert "BatchResult(" in s
        if r.success:
            assert "status=" in s
        else:
            assert "error=" in s

@test("batch with empty list returns empty list")
def _():
    results = client.request_batch([])
    assert results == []

@test("batch concurrency parameter works")
def _():
    results = client.request_batch([
        blasthttp.BatchConfig("https://example.com"),
        blasthttp.BatchConfig("https://example.org"),
    ], concurrency=1)
    assert len(results) == 2


# ── RedirectHop ───────────────────────────────────────────────────

@test("redirect chain contains RedirectHop objects")
def _():
    # httpbin /redirect/1 does a single redirect
    r = client.request("https://httpbin.org/redirect/1", follow_redirects=True)
    assert isinstance(r.redirect_chain, list)
    assert len(r.redirect_chain) >= 1, "expected at least one redirect hop"
    for hop in r.redirect_chain:
        assert isinstance(hop, blasthttp.RedirectHop)
        assert isinstance(hop.url, str)
        assert isinstance(hop.status, int)
        assert hop.status in (301, 302, 303, 307, 308)
    hop_repr = repr(r.redirect_chain[0])
    assert "RedirectHop(" in hop_repr


# ── Multiple clients ──────────────────────────────────────────────

@test("multiple BlastHTTP clients work independently")
def _():
    c1 = blasthttp.BlastHTTP()
    c2 = blasthttp.BlastHTTP()
    r1 = c1.request("https://example.com")
    r2 = c2.request("https://example.org")
    assert r1.status == 200
    assert r2.status == 200


# ── Retry configuration ──────────────────────────────────────────

@test("request() accepts retries kwarg")
def _():
    r = client.request("https://example.com", retries=0)
    assert r.status == 200

@test("request() accepts retry_wait_min_ms kwarg")
def _():
    r = client.request("https://example.com", retry_wait_min_ms=100)
    assert r.status == 200

@test("request() accepts retry_wait_max_ms kwarg")
def _():
    r = client.request("https://example.com", retry_wait_max_ms=5000)
    assert r.status == 200

@test("BatchConfig accepts retry kwargs")
def _():
    cfg = blasthttp.BatchConfig("https://example.com", retries=2, retry_wait_min_ms=100, retry_wait_max_ms=5000)
    assert cfg.retries == 2
    assert cfg.retry_wait_min_ms == 100
    assert cfg.retry_wait_max_ms == 5000

@test("retries=0 still works for connection errors (no retry)")
def _():
    """With retries=0, a connection error should fail immediately."""
    import time
    start = time.time()
    try:
        client.request("https://localhost:1", retries=0, timeout=2)
        assert False, "should have raised"
    except RuntimeError:
        pass
    elapsed = time.time() - start
    # Should fail fast, not retry
    assert elapsed < 3, f"took {elapsed:.1f}s, expected < 3s (no retries)"

@test("retries=0 with timeout fails without retrying")
def _():
    """Timeout errors are never retried regardless of retry setting."""
    import time
    start = time.time()
    try:
        client.request("https://httpbin.org/delay/10", retries=3, timeout=1)
        assert False, "should have raised"
    except RuntimeError as e:
        assert "timed out" in str(e).lower()
    elapsed = time.time() - start
    # Timeout = 1s, should NOT retry (timeout is not retryable)
    assert elapsed < 3, f"took {elapsed:.1f}s, expected < 3s (timeout not retried)"


# ── Rate limiting ─────────────────────────────────────────────────

@test("request_batch() accepts rate_limit parameter")
def _():
    results = client.request_batch([
        blasthttp.BatchConfig("https://example.com"),
    ], rate_limit=100.0)
    assert len(results) == 1
    assert results[0].success

@test("rate_limit=None is unlimited (default)")
def _():
    import time
    configs = [blasthttp.BatchConfig("https://example.com") for _ in range(3)]
    start = time.time()
    results = client.request_batch(configs)
    elapsed = time.time() - start
    assert len(results) == 3
    # No rate limit, should be fast
    assert elapsed < 5, f"unlimited batch took {elapsed:.1f}s"

# ── Debug log ─────────────────────────────────────────────────────

@test("response.debug_log is a list of strings")
def _():
    r = client.request("https://example.com")
    assert isinstance(r.debug_log, list)
    for msg in r.debug_log:
        assert isinstance(msg, str)

@test("debug_log contains request flow messages")
def _():
    r = client.request("https://example.com")
    log_text = "\n".join(r.debug_log)
    # Should contain the request method and URL
    assert "GET" in log_text
    assert "example.com" in log_text

@test("debug_log contains response status")
def _():
    r = client.request("https://example.com")
    log_text = "\n".join(r.debug_log)
    assert "200" in log_text

@test("debug_log contains header info")
def _():
    r = client.request("https://example.com")
    log_text = "\n".join(r.debug_log)
    assert "headers" in log_text.lower() or "Header" in log_text

@test("debug_log contains cert info for HTTPS")
def _():
    r = client.request("https://example.com")
    log_text = "\n".join(r.debug_log)
    assert "Cert" in log_text or "cert" in log_text


@test("rate_limit paces requests")
def _():
    """With a low rate limit, batch should take noticeably longer."""
    import time
    configs = [blasthttp.BatchConfig("https://example.com") for _ in range(4)]

    # Unlimited
    start = time.time()
    client.request_batch(configs, rate_limit=None)
    fast = time.time() - start

    # Rate limited to 5/sec = 200ms between each = ~600ms for 4 requests
    start = time.time()
    results = client.request_batch(configs, rate_limit=5.0)
    slow = time.time() - start

    assert len(results) == 4
    for r in results:
        assert r.success
    # Rate limited should be measurably slower
    assert slow > fast, f"rate limited ({slow:.2f}s) should be slower than unlimited ({fast:.2f}s)"
    # Should take at least ~500ms (3 intervals × 200ms, with some tolerance)
    assert slow >= 0.4, f"rate limited took {slow:.2f}s, expected >= 0.4s"


# ── Download ──────────────────────────────────────────────────────

@test("download() saves file to disk")
def _():
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f:
        path = f.name
    try:
        result = client.download("https://example.com", path)
        assert result == path
        assert os.path.exists(path)
        content = open(path).read()
        assert "Example Domain" in content
        assert len(content) > 100
    finally:
        os.unlink(path)

@test("download() returns the path string")
def _():
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        path = f.name
    try:
        result = client.download("https://example.com", path)
        assert isinstance(result, str)
        assert result == path
    finally:
        os.unlink(path)

@test("download() raises on connection failure")
def _():
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name
    try:
        client.download("https://localhost:1", path)
        assert False, "should have raised"
    except RuntimeError:
        pass
    finally:
        import os
        if os.path.exists(path):
            os.unlink(path)

@test("download() accepts timeout and retries kwargs")
def _():
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f:
        path = f.name
    try:
        result = client.download("https://example.com", path, timeout=30, retries=0)
        assert os.path.exists(path)
    finally:
        os.unlink(path)

@test("download() accepts headers kwarg")
def _():
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f:
        path = f.name
    try:
        result = client.download("https://example.com", path,
                                  headers=[("Accept", "text/html")])
        assert os.path.exists(path)
    finally:
        os.unlink(path)


# ── Summary ───────────────────────────────────────────────────────

print()
print(f"{'='*60}")
print(f"  {passed} passed, {failed} failed")
print(f"{'='*60}")

if errors:
    print("\nFailure details:")
    for name, tb in errors:
        print(f"\n--- {name} ---")
        print(tb)

sys.exit(1 if failed > 0 else 0)
