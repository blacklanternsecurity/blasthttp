"""Pytest-asyncio tests: the proxy / no_proxy decision is re-made on every
redirect hop, not frozen at the first URL.

These exercise the PyO3 bindings with the request(proxy=, no_proxy=,
follow_redirects=True) call shape. Two loopback IPs (127.0.0.1 / 127.0.0.2)
give the two redirect hops distinct host strings that a single no_proxy entry
can tell apart.
"""

import asyncio

import blasthttp
import pytest
import pytest_asyncio


def _http_200(body):
    return (f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}").encode()


def _http_302(location):
    return (f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").encode()


@pytest_asyncio.fixture
async def http_factory():
    """Factory that spawns fixed-response HTTP/1.1 servers and tears them all
    down on cleanup. Each call returns (port, counter), where counter is a
    one-element list bumped once per accepted connection — how we tell whether a
    given host was actually connected to."""
    servers = []

    async def spawn(bind_host, response):
        counter = [0]

        async def handle(reader, writer):
            try:
                # Drain the request head before replying.
                buf = b""
                while b"\r\n\r\n" not in buf and len(buf) < 16384:
                    chunk = await reader.read(512)
                    if not chunk:
                        break
                    buf += chunk
                counter[0] += 1
                writer.write(response)
                await writer.drain()
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(handle, bind_host, 0)
        servers.append(server)
        return server.sockets[0].getsockname()[1], counter

    try:
        yield spawn
    finally:
        for server in servers:
            server.close()
        for server in servers:
            try:
                await server.wait_closed()
            except Exception:
                pass


@pytest.fixture
def client():
    return blasthttp.BlastHTTP()


async def test_redirect_onto_proxied_host_reevaluates_no_proxy(client, http_factory):
    """Case A (no leak): an excluded first host (direct) redirects onto a
    non-excluded host. The post-redirect hop must go through the proxy, not
    connect directly."""
    # Reached only if the post-redirect hop wrongly stays direct.
    target_port, _ = await http_factory("127.0.0.1", _http_200("TARGET_DIRECT"))
    redirect_port, _ = await http_factory("127.0.0.2", _http_302(f"http://127.0.0.1:{target_port}/next"))
    proxy_port, proxy_hits = await http_factory("127.0.0.1", _http_200("VIA_PROXY"))

    r = await client.request(
        f"http://127.0.0.2:{redirect_port}/start",
        proxy=f"http://127.0.0.1:{proxy_port}",
        no_proxy=["127.0.0.2"],
        follow_redirects=True,
    )

    assert r.body == "VIA_PROXY", f"post-redirect hop should be proxied, got {r.body!r}"
    assert proxy_hits[0] == 1, f"proxy should be hit once, got {proxy_hits[0]}"


async def test_redirect_onto_no_proxy_host_reevaluates_to_direct(client, http_factory):
    """Case B: a proxied first host redirects onto an excluded host. The
    post-redirect hop must connect directly, not keep using the proxy."""
    # Excluded redirect target — reached only via a direct connection.
    target_port, direct_hits = await http_factory("127.0.0.2", _http_200("TARGET_DIRECT"))
    # The proxy redirects every request onto the excluded host.
    proxy_port, proxy_hits = await http_factory("127.0.0.1", _http_302(f"http://127.0.0.2:{target_port}/next"))

    # Start host (127.0.0.1) is not excluded -> hop 1 is proxied.
    r = await client.request(
        f"http://127.0.0.1:{proxy_port}/start",
        proxy=f"http://127.0.0.1:{proxy_port}",
        no_proxy=["127.0.0.2"],
        follow_redirects=True,
    )

    assert r.body == "TARGET_DIRECT", f"post-redirect hop should be direct, got {r.body!r}"
    assert direct_hits[0] == 1, f"excluded host should be hit directly once, got {direct_hits[0]}"
    assert proxy_hits[0] == 1, f"proxy should only serve hop 1, got {proxy_hits[0]}"


async def test_no_proxy_without_proxy_raises(client):
    """no_proxy without a proxy is a mistake — it should raise, not silently do
    nothing. Validation runs before any connection, so the URL is never dialed."""
    with pytest.raises(RuntimeError) as exc:
        await client.request("http://127.0.0.1:1/", no_proxy=["127.0.0.1"])
    assert "no_proxy" in str(exc.value)
