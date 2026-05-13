"""Pytest-asyncio tests for blasthttp.RawConnection.

Exercises the Rust-backed byte-pipeline primitive through the PyO3 bindings
using a local asyncio TCP echo server as the peer.
"""

import asyncio
import time

import blasthttp
import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def echo_server():
    """Local asyncio TCP echo server on an ephemeral port.

    Yields (server, port). Server is torn down on fixture cleanup.
    """

    async def handle(reader, writer):
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield server, port
    finally:
        server.close()
        await server.wait_closed()


@pytest.fixture
def client():
    return blasthttp.BlastHTTP()


def test_module_exports_raw_connection():
    assert hasattr(blasthttp, "RawConnection")


async def test_raw_connect_returns_raw_connection(client, echo_server):
    _server, port = echo_server
    conn = await client.raw_connect(f"http://127.0.0.1:{port}")
    assert isinstance(conn, blasthttp.RawConnection)
    await conn.close()


async def test_send_bytes_read_raw_roundtrip(client, echo_server):
    _server, port = echo_server
    conn = await client.raw_connect(f"http://127.0.0.1:{port}")
    await conn.send_bytes(b"hello blasthttp")
    data = await conn.read_raw(1024, timeout_ms=2000)
    assert data == b"hello blasthttp"
    await conn.close()


async def test_read_raw_timeout_returns_empty(client, echo_server):
    _server, port = echo_server
    conn = await client.raw_connect(f"http://127.0.0.1:{port}")
    data = await conn.read_raw(1024, timeout_ms=100)
    assert data == b""
    await conn.close()


async def test_send_bytes_after_close_errors(client, echo_server):
    _server, port = echo_server
    conn = await client.raw_connect(f"http://127.0.0.1:{port}")
    await conn.close()
    with pytest.raises(RuntimeError):
        await conn.send_bytes(b"x")


async def test_read_raw_after_close_errors(client, echo_server):
    _server, port = echo_server
    conn = await client.raw_connect(f"http://127.0.0.1:{port}")
    await conn.close()
    with pytest.raises(RuntimeError):
        await conn.read_raw(1024, timeout_ms=100)


async def test_close_is_idempotent(client, echo_server):
    _server, port = echo_server
    conn = await client.raw_connect(f"http://127.0.0.1:{port}")
    await conn.close()
    await conn.close()


async def test_cert_info_none_for_plain_http(client, echo_server):
    _server, port = echo_server
    conn = await client.raw_connect(f"http://127.0.0.1:{port}")
    assert conn.cert_info is None
    await conn.close()


async def test_multiple_sends_accumulate_at_peer(client, echo_server):
    _server, port = echo_server
    conn = await client.raw_connect(f"http://127.0.0.1:{port}")
    await conn.send_bytes(b"hello ")
    await conn.send_bytes(b"world")
    total = b""
    while len(total) < 11:
        chunk = await conn.read_raw(64, timeout_ms=1000)
        if not chunk:
            break
        total += chunk
    assert total == b"hello world"
    await conn.close()


async def test_connect_to_unreachable_errors(client):
    with pytest.raises(RuntimeError):
        await client.raw_connect("http://127.0.0.1:1")


async def test_rate_limited_connect_succeeds(echo_server):
    _server, port = echo_server
    rl_client = blasthttp.BlastHTTP()
    rl_client.set_rate_limit(10)  # 10 requests per second

    t0 = time.monotonic()
    conn = await rl_client.raw_connect(f"http://127.0.0.1:{port}")
    elapsed = time.monotonic() - t0

    assert isinstance(conn, blasthttp.RawConnection)
    assert elapsed < 1.0, f"rate-limited connect took {elapsed:.2f}s"
    await conn.close()


async def test_rate_limit_tokens_consumed_on_send_and_read(echo_server):
    """RawConnection inherits the originating BlastHTTP's rate limiter:
    `send_bytes` and `read_raw` each consume one token. This prevents a
    single-connection caller from bursting past the configured rate.

    Set 10 RPS (100ms interval). connect + send + read = 3 token
    acquisitions; the first runs immediately, the next two each wait
    ~100ms → total ≥200ms. Allow scheduler slack but require ≥180ms."""
    _server, port = echo_server
    rl_client = blasthttp.BlastHTTP()
    rl_client.set_rate_limit(10)

    t0 = time.monotonic()
    conn = await rl_client.raw_connect(f"http://127.0.0.1:{port}")
    await conn.send_bytes(b"ping")
    _ = await conn.read_raw(1024, timeout_ms=2000)
    elapsed = time.monotonic() - t0
    await conn.close()

    assert elapsed >= 0.18, f"rate limit did not gate send/read: elapsed {elapsed:.3f}s"
