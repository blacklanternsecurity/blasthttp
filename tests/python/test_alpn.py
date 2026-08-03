"""Pytest-asyncio tests for ALPN negotiation via raw_connect.

Exercises the `alpn_protocols` parameter and the `negotiated_alpn`
attribute on the returned RawConnection against a local TLS server
that offers a specific ALPN list.
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
    """Generate a throwaway self-signed certificate in a module-scoped
    tmpdir. Used by every TLS server fixture below. One cert covers all
    tests — we don't care about CN/SAN since verify is off on the
    client side."""
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


def _server_ctx(cert, key, server_alpn_list):
    """TLS server context with a specific ALPN offering. OpenSSL's
    default selection is server-preference first, so the order of
    `server_alpn_list` determines which protocol wins when the client
    offers multiple."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    if server_alpn_list:
        ctx.set_alpn_protocols(server_alpn_list)
    return ctx


@pytest_asyncio.fixture
async def tls_server_factory(selfsigned_cert):
    """Yields an async factory: `await make_server(server_alpn_list)`
    → port. Spawned servers are tracked and torn down after the test
    that used them."""
    cert, key = selfsigned_cert
    servers = []

    async def handle(reader, writer):
        # Accept the handshake, then immediately close. We only care
        # about the ALPN outcome, not any post-handshake traffic.
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def make_server(server_alpn_list):
        ctx = _server_ctx(cert, key, server_alpn_list)
        srv = await asyncio.start_server(
            handle,
            "127.0.0.1",
            0,
            ssl=ctx,
        )
        servers.append(srv)
        return srv.sockets[0].getsockname()[1]

    yield make_server

    for srv in servers:
        srv.close()
        try:
            await srv.wait_closed()
        except Exception:
            pass


@pytest.fixture
def client():
    return blasthttp.BlastHTTP()


async def test_alpn_negotiates_h2_when_only_h2_offered_and_supported(
    client,
    tls_server_factory,
):
    """Server advertises h2; client offers h2 only → negotiated=h2."""
    port = await tls_server_factory(["h2"])
    conn = await client.raw_connect(
        f"https://127.0.0.1:{port}",
        alpn_protocols=["h2"],
    )
    assert conn.negotiated_alpn == "h2"
    await conn.close()


async def test_alpn_negotiates_http1_when_only_http1_offered(
    client,
    tls_server_factory,
):
    """Server advertises http/1.1; client offers http/1.1 only →
    negotiated=http/1.1."""
    port = await tls_server_factory(["http/1.1"])
    conn = await client.raw_connect(
        f"https://127.0.0.1:{port}",
        alpn_protocols=["http/1.1"],
    )
    assert conn.negotiated_alpn == "http/1.1"
    await conn.close()


async def test_alpn_uses_server_preference_order(
    client,
    tls_server_factory,
):
    """Server lists `[http/1.1, h2]` (h1 preferred); client offers
    both `[h2, http/1.1]`. OpenSSL picks server's preferred → h1.
    This is the exact behavior the `hidden_http2` use case depends on."""
    port = await tls_server_factory(["http/1.1", "h2"])
    conn = await client.raw_connect(
        f"https://127.0.0.1:{port}",
        alpn_protocols=["h2", "http/1.1"],
    )
    assert conn.negotiated_alpn == "http/1.1"
    await conn.close()


async def test_alpn_defaults_to_http1_when_not_specified(
    client,
    tls_server_factory,
):
    """Client doesn't pass `alpn_protocols`: blasthttp offers an
    http/1.1 default, so `negotiated_alpn` is "http/1.1" against a
    server that advertises both."""
    port = await tls_server_factory(["h2", "http/1.1"])
    conn = await client.raw_connect(f"https://127.0.0.1:{port}")
    assert conn.negotiated_alpn == "http/1.1"
    await conn.close()


async def test_alpn_negotiated_is_none_when_server_has_no_alpn(
    client,
    tls_server_factory,
):
    """Client offers ALPN, server doesn't advertise any → connection
    still succeeds but `negotiated_alpn` is None."""
    port = await tls_server_factory([])  # server with no ALPN list
    conn = await client.raw_connect(
        f"https://127.0.0.1:{port}",
        alpn_protocols=["h2"],
    )
    assert conn.negotiated_alpn is None
    await conn.close()


async def test_request_alpn_reaches_the_pooled_path(client, selfsigned_cert):
    """`request()` also honors `alpn_protocols`, which is the escape
    hatch for a server that only answers correctly over one protocol.
    Asserted from the server side, since a Response doesn't expose the
    negotiated protocol.

    The server offers both and lets the client's list decide, so what it
    records is what blasthttp actually asked for.
    """
    cert, key = selfsigned_cert
    negotiated = []

    async def handle(reader, writer):
        ssl_obj = writer.get_extra_info("ssl_object")
        negotiated.append(ssl_obj.selected_alpn_protocol() if ssl_obj else None)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    ctx = _server_ctx(cert, key, ["h2", "http/1.1"])
    srv = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    port = srv.sockets[0].getsockname()[1]

    async def negotiate(**kw):
        negotiated.clear()
        # The server hangs up right after the handshake, so the request
        # itself fails. The ALPN outcome is the point.
        try:
            await client.request(f"https://127.0.0.1:{port}/", timeout=10, verify_certs=False, **kw)
        except Exception:
            pass
        return negotiated[0] if negotiated else None

    try:
        assert await negotiate(alpn_protocols=["http/1.1"]) == "http/1.1"
        assert await negotiate(alpn_protocols=["h2"]) == "h2"
        # Unspecified keeps the h2-first default the pooled path has
        # always offered.
        assert await negotiate() == "h2"
    finally:
        srv.close()
        try:
            await srv.wait_closed()
        except Exception:
            pass


async def test_alpn_negotiated_is_none_for_plain_http():
    """Plain HTTP → no TLS → no ALPN. Using the existing local TCP
    echo fixture path rather than the TLS factory."""

    async def handle(reader, writer):
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        client = blasthttp.BlastHTTP()
        conn = await client.raw_connect(
            f"http://127.0.0.1:{port}",
            alpn_protocols=["h2"],
        )
        assert conn.negotiated_alpn is None
        await conn.close()
    finally:
        server.close()
        await server.wait_closed()
