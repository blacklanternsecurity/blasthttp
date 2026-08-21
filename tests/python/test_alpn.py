"""Pytest-asyncio tests for ALPN negotiation.

Exercises the `alpn_protocols` parameter on `raw_connect` and
`request()`, the `negotiated_alpn` attribute on the returned
RawConnection, and which protocol a request actually ends up speaking,
against local TLS servers that offer a specific ALPN list.
"""

import asyncio
import pathlib
import ssl
import subprocess
import tempfile

import blasthttp
import pytest
import pytest_asyncio
from blasthttp import h2


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


async def _serve_one_h2_request(reader, writer, payload):
    """Answer exactly one HTTP/2 request, then stop reading.

    Just enough of RFC 9113 to prove a request was spoken over h2 and not
    HTTP/1.1: exchange SETTINGS, wait for HEADERS, reply with a 200 and a
    body. Built on `blasthttp.h2`'s own frame and HPACK helpers, since the
    test environment has no HTTP/2 server library.
    """
    # Our SETTINGS has to be the first thing the client sees.
    writer.write(h2.build_settings_frame())
    await writer.drain()

    preface = await reader.readexactly(len(h2.PREFACE))
    assert preface == h2.PREFACE, f"client did not speak h2: {preface!r}"

    while True:
        head = await reader.readexactly(9)
        length = int.from_bytes(head[0:3], "big")
        ftype, flags = head[3], head[4]
        stream_id = int.from_bytes(head[5:9], "big") & 0x7FFFFFFF
        if length:
            await reader.readexactly(length)

        if ftype == h2.FRAME_SETTINGS and not flags & h2.FLAG_ACK:
            writer.write(h2.build_settings_frame(ack=True))
            await writer.drain()
        elif ftype == h2.FRAME_HEADERS:
            block = h2.encode_headers(
                [
                    h2.Header(":status", "200"),
                    h2.Header("content-type", "text/plain"),
                    h2.Header("content-length", str(len(payload))),
                ]
            )
            writer.write(h2.build_headers_frame(block, stream_id=stream_id))
            writer.write(h2.build_data_frame(payload, stream_id=stream_id, end_stream=True))
            await writer.drain()
            # Hang up once the response is on the wire. The client pools
            # h2 connections and would otherwise hold this one open, and
            # from 3.12 on `Server.wait_closed()` waits for open
            # connections, so the fixture teardown would never finish.
            writer.close()
            return


@pytest_asyncio.fixture
async def h2_server(selfsigned_cert):
    """Yields an async factory: `await make_server(payload)` → port. The
    server negotiates h2 only, so a client that offers anything else
    fails the handshake rather than quietly falling back."""
    cert, key = selfsigned_cert
    servers = []

    async def make_server(payload):
        async def handle(reader, writer):
            try:
                await _serve_one_h2_request(reader, writer, payload)
            except Exception:
                pass

        ctx = _server_ctx(cert, key, ["h2"])
        srv = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
        servers.append(srv)
        return srv.sockets[0].getsockname()[1]

    yield make_server

    for srv in servers:
        srv.close()
        try:
            await srv.wait_closed()
        except Exception:
            pass


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


async def test_request_speaks_h2_on_the_pooled_path(client, h2_server):
    """The ordinary path: no `resolve_ip`, no `request_target`, so the
    request goes through the connection pool."""
    port = await h2_server(b"served over h2")
    r = await client.request(
        f"https://127.0.0.1:{port}/",
        timeout=10,
        verify_certs=False,
        alpn_protocols=["h2"],
    )
    assert r.status_code == 200
    assert r.content == b"served over h2"


async def test_request_speaks_h2_on_the_direct_path(client, h2_server):
    """`resolve_ip` routes around the pool, and that path negotiated h2
    and then sent HTTP/1.1 over it, which a server can only answer by
    hanging up. Pinning the combination here because DNS pinning and
    protocol choice are independent things a caller may want together."""
    port = await h2_server(b"h2 with a pinned ip")
    r = await client.request(
        f"https://127.0.0.1:{port}/",
        timeout=10,
        verify_certs=False,
        resolve_ip="127.0.0.1",
        alpn_protocols=["h2"],
    )
    assert r.status_code == 200
    assert r.content == b"h2 with a pinned ip"


async def test_direct_path_still_defaults_to_http1(client, selfsigned_cert):
    """With no `alpn_protocols`, the `resolve_ip` path offers http/1.1
    alone even against a server that would take h2. The offer is part of
    the client's TLS fingerprint, so this default is behavior that the
    existing callers of this path depend on, not a detail."""
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
    try:
        # The server hangs up right after the handshake, so the request
        # itself fails. The ALPN outcome is the point.
        try:
            await client.request(
                f"https://127.0.0.1:{port}/",
                timeout=10,
                verify_certs=False,
                resolve_ip="127.0.0.1",
            )
        except Exception:
            pass
        # The server hangs up, so the client retries and connects more
        # than once. Every attempt has to have offered the same list.
        assert negotiated, "server saw no connection"
        assert set(negotiated) == {"http/1.1"}
    finally:
        srv.close()
        try:
            await srv.wait_closed()
        except Exception:
            pass


async def test_request_target_with_an_h2_offer_is_refused(client, tls_server_factory):
    """`request_target` exists to control the request-line, and HTTP/2
    doesn't have one: hyper builds `:path` from the URI. Say so instead
    of sending something other than what was asked for."""
    port = await tls_server_factory(["h2"])
    with pytest.raises(RuntimeError, match="request_target cannot be sent over HTTP/2"):
        await client.request(
            f"https://127.0.0.1:{port}/",
            timeout=10,
            verify_certs=False,
            request_target="http://example.com/admin",
            alpn_protocols=["h2"],
        )


async def test_request_target_over_http1_is_unaffected(client, tls_server_factory):
    """The same request with an http/1.1 offer still goes out, since
    that's the path `request_target` was built for."""
    port = await tls_server_factory(["http/1.1"])
    # The server hangs up after the handshake, so this fails on the
    # response, not on the parameter combination.
    with pytest.raises(RuntimeError) as excinfo:
        await client.request(
            f"https://127.0.0.1:{port}/",
            timeout=10,
            verify_certs=False,
            request_target="http://example.com/admin",
            alpn_protocols=["http/1.1"],
        )
    assert "request_target cannot be sent" not in str(excinfo.value)


async def test_batch_config_honors_alpn_protocols(client, selfsigned_cert):
    """`BatchConfig` takes the same parameters as `request()`, and the batch
    API is the main scanning surface, so the documented escape hatch for a
    server that only answers over HTTP/1.1 has to be reachable from it."""
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
    try:
        config = blasthttp.BatchConfig(
            f"https://127.0.0.1:{port}/",
            timeout=10,
            verify_certs=False,
            alpn_protocols=["http/1.1"],
        )
        # The server hangs up after the handshake, so the request fails. The
        # ALPN outcome is the point.
        await client.request_batch([config], concurrency=1)
        assert negotiated, "server saw no connection"
        assert set(negotiated) == {"http/1.1"}
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
