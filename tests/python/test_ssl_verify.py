"""Tests for SSL certificate verification across all connection types.

Covers: request, request_batch, request_batch_stream, raw_connect, download.
Verifies that verify_certs=True rejects self-signed certs and verify_certs=False
accepts them. Also tests that the client cache correctly isolates connections
with different verify settings.
"""

import asyncio
import pathlib
import ssl
import subprocess
import tempfile

import blasthttp
import pytest
import pytest_asyncio


@pytest.fixture(scope="module")
def selfsigned_cert():
    tmpdir = tempfile.mkdtemp()
    cert = pathlib.Path(tmpdir) / "cert.pem"
    key = pathlib.Path(tmpdir) / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
        ],
        check=True,
        capture_output=True,
    )
    return str(cert), str(key)


def _make_server_ctx(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


RESPONSE_BODY = "ssl-verify-test-ok"
HTTP_RESPONSE = (
    f"HTTP/1.1 200 OK\r\nContent-Length: {len(RESPONSE_BODY)}\r\nConnection: close\r\n\r\n{RESPONSE_BODY}"
).encode()


@pytest_asyncio.fixture
async def tls_server(selfsigned_cert):
    """Single-connection TLS server on an ephemeral port."""
    cert, key = selfsigned_cert
    ctx = _make_server_ctx(cert, key)

    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
        except Exception:
            pass
        writer.write(HTTP_RESPONSE)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


@pytest_asyncio.fixture
async def tls_multi_server(selfsigned_cert):
    """Multi-connection TLS server for batch tests."""
    cert, key = selfsigned_cert
    ctx = _make_server_ctx(cert, key)

    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
        except Exception:
            pass
        writer.write(HTTP_RESPONSE)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


@pytest.fixture
def client():
    return blasthttp.BlastHTTP()


# ── request() ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_request_verify_true_rejects_self_signed(client, tls_server):
    url = f"https://127.0.0.1:{tls_server}/"
    with pytest.raises(RuntimeError):
        await client.request(url, verify_certs=True, timeout=5)


@pytest.mark.asyncio
async def test_request_verify_false_accepts_self_signed(client, tls_server):
    url = f"https://127.0.0.1:{tls_server}/"
    r = await client.request(url, verify_certs=False, timeout=5)
    assert r.status_code == 200
    assert r.text == RESPONSE_BODY


# ── request_batch() ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_request_batch_verify_true_rejects_self_signed(client, tls_multi_server):
    url = f"https://127.0.0.1:{tls_multi_server}/"
    configs = [blasthttp.BatchConfig(url, verify_certs=True, timeout=5)]
    results = await client.request_batch(configs)
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error is not None


@pytest.mark.asyncio
async def test_request_batch_verify_false_accepts_self_signed(client, tls_multi_server):
    url = f"https://127.0.0.1:{tls_multi_server}/"
    configs = [blasthttp.BatchConfig(url, verify_certs=False, timeout=5)]
    results = await client.request_batch(configs)
    assert len(results) == 1
    assert results[0].success is True
    assert results[0].response.status_code == 200


# ── request_batch_stream() ────────────────────────────────────────


@pytest.mark.asyncio
async def test_request_batch_stream_verify_true_rejects_self_signed(client, tls_multi_server):
    url = f"https://127.0.0.1:{tls_multi_server}/"
    configs = [blasthttp.BatchConfig(url, verify_certs=True, timeout=5)]
    results = []
    async for batch in client.request_batch_stream(configs):
        results.extend(batch)
    assert len(results) == 1
    assert results[0].success is False


@pytest.mark.asyncio
async def test_request_batch_stream_verify_false_accepts_self_signed(client, tls_multi_server):
    url = f"https://127.0.0.1:{tls_multi_server}/"
    configs = [blasthttp.BatchConfig(url, verify_certs=False, timeout=5)]
    results = []
    async for batch in client.request_batch_stream(configs):
        results.extend(batch)
    assert len(results) == 1
    assert results[0].success is True
    assert results[0].response.status_code == 200


# ── raw_connect() ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_raw_connect_verify_true_rejects_self_signed(client, tls_server):
    url = f"https://127.0.0.1:{tls_server}/"
    with pytest.raises(RuntimeError):
        await client.raw_connect(url, verify_certs=True, timeout=5)


@pytest.mark.asyncio
async def test_raw_connect_verify_false_accepts_self_signed(client, tls_server):
    url = f"https://127.0.0.1:{tls_server}/"
    conn = await client.raw_connect(url, verify_certs=False, timeout=5)
    assert isinstance(conn, blasthttp.RawConnection)
    await conn.close()


# ── download() ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_download_verify_true_rejects_self_signed(client, tls_server, tmp_path):
    url = f"https://127.0.0.1:{tls_server}/file.txt"
    dest = str(tmp_path / "out.txt")
    with pytest.raises(RuntimeError):
        await client.download(url, dest, verify_certs=True, timeout=5)


@pytest.mark.asyncio
async def test_download_verify_false_accepts_self_signed(client, tls_server, tmp_path):
    url = f"https://127.0.0.1:{tls_server}/file.txt"
    dest = str(tmp_path / "out.txt")
    await client.download(url, dest, verify_certs=False, timeout=5)
    assert pathlib.Path(dest).read_text() == RESPONSE_BODY


# ── raw_connect timeout ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_raw_connect_timeout_fires():
    """Connect to a non-routable IP with a short timeout to verify the
    timeout parameter works."""
    client = blasthttp.BlastHTTP()
    import time

    t0 = time.monotonic()
    with pytest.raises(RuntimeError):
        await client.raw_connect("https://192.0.2.1:443/", timeout=2)
    elapsed = time.monotonic() - t0
    assert elapsed < 5, f"timeout took {elapsed:.1f}s, expected ~2s"


# ── Client cache isolation ────────────────────────────────────────


@pytest.mark.asyncio
async def test_cache_isolation_verify_false_then_true(tls_multi_server):
    """After a verify=False request succeeds, a verify=True request to the
    same host must still fail. This catches the bug where ConnMode didn't
    include verify_certs in the cache key."""
    client = blasthttp.BlastHTTP()
    url = f"https://127.0.0.1:{tls_multi_server}/"

    r = await client.request(url, verify_certs=False, timeout=5)
    assert r.status_code == 200

    with pytest.raises(RuntimeError):
        await client.request(url, verify_certs=True, timeout=5)
