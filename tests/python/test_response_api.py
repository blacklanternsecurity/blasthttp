"""Tests for the httpx-style Response API: Headers, Request, json,
raise_for_status, lazy caching, and the field aliases (status_code,
text, content, elapsed)."""

import asyncio
import datetime

import pytest
import pytest_asyncio
import blasthttp


# ── Local HTTP server fixture ────────────────────────────────────


async def _http_handler(reader, writer):
    """Handler that responds based on the path:
    /              -> 200 OK with "hello"
    /json          -> 200 OK with a JSON body
    /404           -> 404 Not Found
    /500           -> 500 Internal Server Error
    /cookies       -> two Set-Cookie headers
    /multi-headers -> duplicate header names
    """
    try:
        request_line = await reader.readuntil(b"\r\n")
        # Drain the rest of the headers
        while True:
            line = await reader.readuntil(b"\r\n")
            if line == b"\r\n":
                break

        try:
            _method, path, _ver = request_line.decode().split(" ", 2)
        except ValueError:
            path = "/"

        if path == "/json":
            body = b'{"key": "value", "n": 42}'
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )
        elif path == "/404":
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        elif path == "/500":
            writer.write(b"HTTP/1.1 500 Server Error\r\nContent-Length: 0\r\n\r\n")
        elif path == "/cookies":
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Set-Cookie: a=1; Path=/\r\n"
                b"Set-Cookie: b=2; HttpOnly\r\n"
                b"Content-Length: 2\r\n"
                b"\r\nok"
            )
        elif path == "/multi-headers":
            writer.write(b"HTTP/1.1 200 OK\r\nX-Custom: first\r\nX-Custom: second\r\nContent-Length: 2\r\n\r\nok")
        else:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


@pytest_asyncio.fixture
async def server():
    srv = await asyncio.start_server(_http_handler, "127.0.0.1", 0)
    addr = srv.sockets[0].getsockname()
    base_url = f"http://{addr[0]}:{addr[1]}"
    try:
        yield base_url
    finally:
        srv.close()
        await srv.wait_closed()


@pytest_asyncio.fixture
async def client():
    return blasthttp.BlastHTTP()


# ── Field aliases ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_status_code_alias(client, server):
    r = await client.request(f"{server}/")
    assert r.status == 200
    assert r.status_code == 200
    assert r.status_code == r.status


@pytest.mark.asyncio
async def test_text_alias(client, server):
    r = await client.request(f"{server}/")
    assert r.text == "hello"
    assert r.text == r.body


@pytest.mark.asyncio
async def test_content_alias(client, server):
    r = await client.request(f"{server}/")
    assert bytes(r.content) == b"hello"
    assert bytes(r.content) == bytes(r.body_bytes)


@pytest.mark.asyncio
async def test_is_success(client, server):
    r = await client.request(f"{server}/")
    assert r.is_success is True
    r404 = await client.request(f"{server}/404")
    assert r404.is_success is False


@pytest.mark.asyncio
async def test_elapsed_is_timedelta(client, server):
    r = await client.request(f"{server}/")
    assert isinstance(r.elapsed, datetime.timedelta)
    assert r.elapsed.total_seconds() * 1000 == pytest.approx(r.elapsed_ms, abs=1)


@pytest.mark.asyncio
async def test_response_is_truthy(client, server):
    r = await client.request(f"{server}/404")
    # Even non-success responses are truthy — same as httpx
    assert bool(r) is True


# ── Request shim ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_request_url_and_method(client, server):
    url = f"{server}/"
    r = await client.request(url, method="GET")
    assert r.request.url == url
    assert r.request.method == "GET"


@pytest.mark.asyncio
async def test_request_is_cached(client, server):
    r = await client.request(f"{server}/")
    assert r.request is r.request


# ── Headers (case-insensitive, mutable) ──────────────────────────


@pytest.mark.asyncio
async def test_headers_is_Headers_class(client, server):
    r = await client.request(f"{server}/")
    assert isinstance(r.headers, blasthttp.Headers)


@pytest.mark.asyncio
async def test_headers_case_insensitive_lookup(client, server):
    r = await client.request(f"{server}/")
    h = r.headers
    assert h["Content-Type"] == h["content-type"] == h["CONTENT-TYPE"]


@pytest.mark.asyncio
async def test_headers_is_mutable_mapping(client, server):
    """Headers must register as a MutableMapping so libraries that
    special-case mappings (DeepDiff, dataclasses, etc.) recognize it."""
    from collections.abc import Mapping, MutableMapping

    r = await client.request(f"{server}/")
    assert isinstance(r.headers, Mapping)
    assert isinstance(r.headers, MutableMapping)
    # `dict(headers)` should produce a plain dict snapshot
    snapshot = dict(r.headers)
    assert isinstance(snapshot, dict)
    assert "content-type" in snapshot


@pytest.mark.asyncio
async def test_headers_contains(client, server):
    r = await client.request(f"{server}/")
    assert "Content-Type" in r.headers
    assert "content-type" in r.headers
    assert "x-totally-missing" not in r.headers


@pytest.mark.asyncio
async def test_headers_get_with_default(client, server):
    r = await client.request(f"{server}/")
    assert r.headers.get("Content-Type")
    assert r.headers.get("missing") is None
    assert r.headers.get("missing", "fallback") == "fallback"


@pytest.mark.asyncio
async def test_headers_iter_yields_keys(client, server):
    r = await client.request(f"{server}/")
    keys = list(r.headers)
    # Python dict convention: __iter__ yields keys, not tuples
    assert all(isinstance(k, str) for k in keys)
    assert "content-type" in keys


@pytest.mark.asyncio
async def test_headers_items_yields_tuples_with_duplicates(client, server):
    r = await client.request(f"{server}/multi-headers")
    items = r.headers.items()
    # Duplicates preserved with original casing
    custom_values = [v for k, v in items if k.lower() == "x-custom"]
    assert custom_values == ["first", "second"]


@pytest.mark.asyncio
async def test_headers_mutation_persists(client, server):
    r = await client.request(f"{server}/")
    h = r.headers
    h["X-New"] = "value"
    # Same instance returned next access — mutation visible
    assert r.headers is h
    assert r.headers["X-New"] == "value"


@pytest.mark.asyncio
async def test_headers_delete(client, server):
    r = await client.request(f"{server}/")
    h = r.headers
    h["X-Tmp"] = "x"
    assert "X-Tmp" in h
    del h["X-Tmp"]
    assert "X-Tmp" not in h


@pytest.mark.asyncio
async def test_headers_keyerror_on_missing(client, server):
    r = await client.request(f"{server}/")
    with pytest.raises(KeyError):
        _ = r.headers["definitely-not-present"]


# ── Lazy caching ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_headers_cached_same_instance(client, server):
    r = await client.request(f"{server}/")
    # Reading .headers twice returns the SAME Python object
    assert r.headers is r.headers


@pytest.mark.asyncio
async def test_request_cached_same_instance(client, server):
    r = await client.request(f"{server}/")
    assert r.request is r.request


@pytest.mark.asyncio
async def test_hash_lazy_consistent(client, server):
    r = await client.request(f"{server}/")
    # Repeated reads return the same hash values (cache hit)
    h1 = r.hash
    h2 = r.hash
    assert h1.body_md5 == h2.body_md5


@pytest.mark.asyncio
async def test_raw_headers_format(client, server):
    r = await client.request(f"{server}/")
    raw = r.raw_headers
    assert "content-type" in raw.lower()
    assert "\r\n" in raw  # join separator
    assert not raw.endswith("\r\n")  # no trailing CRLF


# ── Cookies (Rust-side parse) ────────────────────────────────────


@pytest.mark.asyncio
async def test_cookies_parsed(client, server):
    r = await client.request(f"{server}/cookies")
    assert r.cookies == {"a": "1", "b": "2"}


@pytest.mark.asyncio
async def test_cookies_empty_when_none(client, server):
    r = await client.request(f"{server}/")
    assert r.cookies == {}


# ── json() ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_json_decodes_body(client, server):
    r = await client.request(f"{server}/json")
    data = r.json()
    assert data == {"key": "value", "n": 42}


@pytest.mark.asyncio
async def test_json_raises_on_invalid(client, server):
    r = await client.request(f"{server}/")  # body is "hello"
    with pytest.raises(Exception):
        r.json()


# ── raise_for_status() ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_raise_for_status_noop_on_2xx(client, server):
    r = await client.request(f"{server}/")
    r.raise_for_status()  # no exception


@pytest.mark.asyncio
async def test_raise_for_status_4xx(client, server):
    r = await client.request(f"{server}/404")
    with pytest.raises(blasthttp.HTTPStatusError) as excinfo:
        r.raise_for_status()
    assert "404" in str(excinfo.value)
    # Exception carries a reference back to the response
    assert excinfo.value.response.status_code == 404
    assert excinfo.value.response.url == f"{server}/404"


@pytest.mark.asyncio
async def test_raise_for_status_5xx(client, server):
    r = await client.request(f"{server}/500")
    with pytest.raises(blasthttp.HTTPStatusError):
        r.raise_for_status()
