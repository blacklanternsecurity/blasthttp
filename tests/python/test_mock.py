"""Tests for `blasthttp.mock` — the test-fixture mock submodule.

Covers: response/callback registration, sync + async callbacks, regex
URL matching, header/json predicates, FIFO + recycle, batch streaming,
unmatched-URL error path, isinstance checks, pass-through to a real
client, and `should_intercept` predicates.
"""

import asyncio
import re

import pytest

import blasthttp
from blasthttp.mock import (
    BlasthttpMock,
    MockRequest,
    MockResponse,
    TimeoutException,
)


# ── add_response ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_add_response_basic_text():
    mock = BlasthttpMock()
    mock.add_response(url="http://example.com/", text="hi")
    r = await mock.request("http://example.com/")
    assert r.status_code == 200
    assert r.text == "hi"
    assert r.headers["Content-Type"] == "text/plain; charset=utf-8"
    assert isinstance(r, blasthttp.Response)


@pytest.mark.asyncio
async def test_add_response_json():
    mock = BlasthttpMock()
    mock.add_response(url="http://x/", json={"a": 1, "b": [2, 3]})
    r = await mock.request("http://x/")
    assert r.headers["Content-Type"] == "application/json"
    assert r.json() == {"a": 1, "b": [2, 3]}


@pytest.mark.asyncio
async def test_add_response_content_bytes():
    mock = BlasthttpMock()
    mock.add_response(url="http://x/", content=b"\x00\x01\x02")
    r = await mock.request("http://x/")
    assert r.headers["Content-Type"] == "application/octet-stream"
    assert bytes(r.content) == b"\x00\x01\x02"


@pytest.mark.asyncio
async def test_add_response_content_binary_roundtrip():
    # Bytes with the high bit set must round-trip without UTF-8 corruption.
    # All 256 byte values, plus a representative ZIP local-file-header
    # (PK\x03\x04...) — the kind of payload that breaks if the body is
    # passed through a lossy UTF-8 decode.
    mock = BlasthttpMock()
    raw = bytes(range(256)) + b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
    mock.add_response(url="http://x/", content=raw)
    r = await mock.request("http://x/")
    assert bytes(r.content) == raw
    assert len(r.content) == len(raw)


@pytest.mark.asyncio
async def test_add_response_custom_status_and_headers():
    mock = BlasthttpMock()
    mock.add_response(
        url="http://x/",
        status_code=418,
        text="teapot",
        headers={"X-Custom": "v1", "Server": "nginx"},
    )
    r = await mock.request("http://x/")
    assert r.status_code == 418
    assert r.text == "teapot"
    assert r.headers["X-Custom"] == "v1"
    assert r.headers["Server"] == "nginx"


@pytest.mark.asyncio
async def test_add_response_no_url_matches_anything():
    mock = BlasthttpMock()
    mock.add_response(text="anything")
    r1 = await mock.request("http://a/")
    r2 = await mock.request("http://b/")
    assert r1.text == "anything"
    assert r2.text == "anything"


# ── URL matching ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_url_exact_match():
    mock = BlasthttpMock()
    mock.add_response(url="http://exact/path", text="match")
    r = await mock.request("http://exact/path")
    assert r.text == "match"


@pytest.mark.asyncio
async def test_url_exact_no_match_falls_through():
    mock = BlasthttpMock()
    mock.add_response(url="http://a/", text="a")
    with pytest.raises(Exception):
        await mock.request("http://b/")


@pytest.mark.asyncio
async def test_url_regex_match():
    mock = BlasthttpMock()
    mock.add_response(url=re.compile(r"/api/v\d+"), text="api")
    r = await mock.request("http://x/api/v1/users")
    assert r.text == "api"


@pytest.mark.asyncio
async def test_url_regex_no_match():
    mock = BlasthttpMock()
    mock.add_response(url=re.compile(r"/api/"), text="api")
    with pytest.raises(Exception):
        await mock.request("http://x/static/")


# ── Method matching ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_method_filter_matches():
    mock = BlasthttpMock()
    mock.add_response(method="POST", text="posted")
    r = await mock.request("http://x/", method="POST")
    assert r.text == "posted"


@pytest.mark.asyncio
async def test_method_filter_case_insensitive():
    mock = BlasthttpMock()
    mock.add_response(method="post", text="ok")
    r = await mock.request("http://x/", method="POST")
    assert r.text == "ok"


@pytest.mark.asyncio
async def test_method_filter_mismatch_falls_through():
    mock = BlasthttpMock()
    mock.add_response(method="POST", text="ok")
    with pytest.raises(Exception):
        await mock.request("http://x/", method="GET")


# ── Header / JSON predicates ─────────────────────────────────────


@pytest.mark.asyncio
async def test_match_headers_subset():
    mock = BlasthttpMock()
    mock.add_response(text="auth-ok", match_headers={"Authorization": "Bearer x"})
    r = await mock.request("http://x/", headers={"Authorization": "Bearer x", "X-Other": "y"})
    assert r.text == "auth-ok"


@pytest.mark.asyncio
async def test_match_headers_missing_falls_through():
    mock = BlasthttpMock()
    mock.add_response(text="auth-ok", match_headers={"Authorization": "Bearer x"})
    with pytest.raises(Exception):
        await mock.request("http://x/")


@pytest.mark.asyncio
async def test_match_json_subset():
    mock = BlasthttpMock()
    mock.add_response(text="json-ok", match_json={"action": "create"})
    import json as _json

    r = await mock.request("http://x/", method="POST", body=_json.dumps({"action": "create", "extra": 1}))
    assert r.text == "json-ok"


@pytest.mark.asyncio
async def test_match_json_mismatch_falls_through():
    mock = BlasthttpMock()
    mock.add_response(text="json-ok", match_json={"action": "create"})
    import json as _json

    with pytest.raises(Exception):
        await mock.request("http://x/", method="POST", body=_json.dumps({"action": "delete"}))


# ── Callbacks ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sync_callback_returns_mock_response():
    mock = BlasthttpMock()

    def cb(req):
        assert isinstance(req, MockRequest)
        assert req.method == "POST"
        return MockResponse(status_code=201, text="created")

    mock.add_callback(cb)
    r = await mock.request("http://x/", method="POST")
    assert r.status_code == 201
    assert r.text == "created"


@pytest.mark.asyncio
async def test_async_callback_returns_mock_response():
    mock = BlasthttpMock()

    async def cb(req):
        await asyncio.sleep(0)
        return MockResponse(status_code=202, text="accepted")

    mock.add_callback(cb)
    r = await mock.request("http://x/")
    assert r.status_code == 202
    assert r.text == "accepted"


@pytest.mark.asyncio
async def test_callback_can_return_blasthttp_response():
    """Callback returning a `blasthttp.Response` directly should pass through."""
    mock = BlasthttpMock()

    def cb(req):
        return blasthttp.Response(url=req.url, status=204, body=b"", request_method=req.method)

    mock.add_callback(cb)
    r = await mock.request("http://x/")
    assert r.status_code == 204
    assert isinstance(r, blasthttp.Response)


@pytest.mark.asyncio
async def test_callback_url_filter():
    mock = BlasthttpMock()

    def cb(req):
        return MockResponse(text="cb-only-here")

    mock.add_callback(cb, url="http://target/")
    mock.add_response(text="default")
    r1 = await mock.request("http://target/")
    r2 = await mock.request("http://other/")
    assert r1.text == "cb-only-here"
    assert r2.text == "default"


@pytest.mark.asyncio
async def test_callback_propagates_exception():
    mock = BlasthttpMock()

    def cb(req):
        raise ValueError("boom")

    mock.add_callback(cb)
    with pytest.raises(ValueError, match="boom"):
        await mock.request("http://x/")


@pytest.mark.asyncio
async def test_callback_can_raise_timeout():
    mock = BlasthttpMock()

    def cb(req):
        raise TimeoutException("simulated timeout")

    mock.add_callback(cb)
    with pytest.raises(TimeoutException):
        await mock.request("http://x/")


# ── FIFO + recycle ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fifo_consumption_then_recycle():
    mock = BlasthttpMock()
    mock.add_response(text="first")
    mock.add_response(text="second")
    a = await mock.request("http://x/")
    b = await mock.request("http://x/")
    # Both primary handlers consumed; further calls recycle in FIFO order.
    c = await mock.request("http://x/")
    assert (a.text, b.text, c.text) == ("first", "second", "first")


# ── Batch streaming ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_batch_stream_yields_per_config_in_input_order():
    mock = BlasthttpMock()
    mock.add_response(url="http://a/", text="A")
    mock.add_response(url="http://b/", text="B")
    configs = [
        blasthttp.BatchConfig("http://a/"),
        blasthttp.BatchConfig("http://b/"),
    ]
    received = []
    async for r in mock.request_batch_stream(configs):
        received.append((r.url, r.response.text))
    assert received == [("http://a/", "A"), ("http://b/", "B")]


@pytest.mark.asyncio
async def test_batch_request_drains_to_list():
    mock = BlasthttpMock()
    mock.add_response(url="http://a/", text="A")
    mock.add_response(url="http://b/", text="B")
    results = await mock.request_batch([blasthttp.BatchConfig("http://a/"), blasthttp.BatchConfig("http://b/")])
    assert [(r.url, r.response.text) for r in results] == [
        ("http://a/", "A"),
        ("http://b/", "B"),
    ]


@pytest.mark.asyncio
async def test_batch_unmatched_url_yields_error_result():
    mock = BlasthttpMock()
    results = await mock.request_batch([blasthttp.BatchConfig("http://nothing/")])
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error is not None
    assert "No mock response" in results[0].error


# ── should_intercept + pass-through ──────────────────────────────


@pytest.mark.asyncio
async def test_should_intercept_default_intercepts_all():
    mock = BlasthttpMock()
    assert mock.should_intercept("http://anything/") is True


@pytest.mark.asyncio
async def test_should_intercept_with_predicate():
    mock = BlasthttpMock(should_mock_fn=lambda host: host != "127.0.0.1")
    assert mock.should_intercept("http://example.com/") is True
    assert mock.should_intercept("http://127.0.0.1/") is False


@pytest.mark.asyncio
async def test_passthrough_raises_without_real_client():
    mock = BlasthttpMock(should_mock_fn=lambda host: host != "127.0.0.1")
    # 127.0.0.1 is excluded by the predicate but no real_client → error.
    with pytest.raises(Exception, match="real_client"):
        await mock.request("http://127.0.0.1/")


@pytest.mark.asyncio
async def test_passthrough_to_real_client():
    """When should_mock returns False and a real_client is provided,
    requests are forwarded. We use a small local HTTP server fixture."""

    # Local HTTP server returning a fixed body.
    async def handler(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nrealhit")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    addr = server.sockets[0].getsockname()
    base = f"http://{addr[0]}:{addr[1]}/"
    try:
        real = blasthttp.BlastHTTP()
        mock = BlasthttpMock(real_client=real, should_mock_fn=lambda host: host != "127.0.0.1")
        # Mock handler for non-localhost (would be intercepted)
        mock.add_response(url="http://example.com/", text="mocked")

        # localhost should pass through to real_client
        r = await mock.request(base)
        assert r.text == "realhit"

        # non-localhost should be mocked
        r2 = await mock.request("http://example.com/")
        assert r2.text == "mocked"
    finally:
        server.close()
        await server.wait_closed()
