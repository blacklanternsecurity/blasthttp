"""The 1.0 Python surface: connection profiles, and the report a caller reads
to decide what to do next.

This is the contract BBOT consumes. It had no test coverage at all until this
file, which mattered more than usual because the interesting part is not
whether a request succeeds but whether a *failure* is legible enough to act
on, and that is exactly the path nothing exercised.

Everything here runs against a local server, so it is deterministic and needs
no network. What it cannot cover locally is the ladder actually shifting
profiles against a real protection product; the Rust integration tests do that
against a TLS server that can refuse a handshake, and `bench/` does it against
real sites.
"""

import asyncio

import pytest
import pytest_asyncio

import blasthttp


# ── Local server ─────────────────────────────────────────────────


async def _handler(reader, writer):
    """Serves paths that stand in for the things a caller has to tell apart.

    /              ordinary 200
    /echo-headers  200 whose body is the request headers it received
    /cf-challenge  403 shaped like a Cloudflare managed challenge
    /akamai-block  403 shaped like an Akamai edge refusal
    /plain-403     403 with no product signature at all
    """
    try:
        request_line = await reader.readuntil(b"\r\n")
        received = []
        while True:
            line = await reader.readuntil(b"\r\n")
            if line == b"\r\n":
                break
            received.append(line.decode("latin1").rstrip("\r\n"))

        try:
            _method, path, _ver = request_line.decode().split(" ", 2)
        except ValueError:
            path = "/"

        def respond(status, headers, body):
            raw = f"HTTP/1.1 {status} X\r\n".encode()
            for k, v in headers:
                raw += f"{k}: {v}\r\n".encode()
            raw += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            raw += b"Connection: close\r\n\r\n" + body
            writer.write(raw)

        if path == "/echo-headers":
            body = "\n".join(received).encode()
            respond(200, [("Content-Type", "text/plain")], body)
        elif path == "/cf-challenge":
            # cf-mitigated is the header Cloudflare sets specifically to say it
            # intervened, and is what separates a challenge from a WAF block.
            respond(
                403,
                [("server", "cloudflare"), ("cf-mitigated", "challenge")],
                b"<html>Just a moment...</html>",
            )
        elif path == "/akamai-block":
            # No `server` header at all, which is what www.akamai.com's own 403
            # actually sends, and the reason a rule keyed on it matched nothing.
            respond(
                403,
                [("akamai-grn", "0.6d551702.1790644996.315f62a4")],
                b"<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD></HTML>",
            )
        elif path == "/plain-403":
            respond(403, [("server", "nginx")], b"forbidden")
        else:
            respond(200, [("Content-Type", "text/plain")], b"hello")

        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


@pytest_asyncio.fixture
async def server():
    srv = await asyncio.start_server(_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    async with srv:
        yield f"http://127.0.0.1:{port}"


@pytest.fixture
def client():
    return blasthttp.BlastHTTP()


# ── Profiles ─────────────────────────────────────────────────────


async def test_default_profile_sends_an_honest_user_agent(server, client):
    """The default claims nothing. That is the whole point of it: claiming to
    be a browser selects which scrutiny applies, and a client that cannot back
    the claim is worse off than one that never made it."""
    r = await client.request(f"{server}/echo-headers")
    assert "blasthttp/" in r.text
    assert "Mozilla/5.0" not in r.text


async def test_chrome_profile_sends_browser_headers_in_order(server, client):
    r = await client.request(f"{server}/echo-headers", profile="chrome")
    sent = [line.split(":", 1)[0].lower() for line in r.text.splitlines() if ":" in line]

    assert "Mozilla/5.0" in r.text
    for expected in ("sec-ch-ua", "sec-fetch-dest", "accept-language", "priority"):
        assert expected in sent, f"{expected} missing: {sent}"

    # Order is part of the fingerprint, not decoration, so a profile whose
    # headers arrive shuffled has not been applied properly.
    assert sent.index("sec-ch-ua") < sent.index("user-agent") < sent.index("accept")


async def test_compatibility_profile_is_also_honest(server, client):
    r = await client.request(f"{server}/echo-headers", profile="compatibility")
    assert "blasthttp/" in r.text
    assert "Mozilla/5.0" not in r.text


async def test_unknown_profile_is_an_error(server, client):
    """It used to resolve silently to the default, so a typo bought you
    whatever that was with nothing said about it. Once the choice of profile
    decides whether a request gets inspected, that is not a good trade."""
    with pytest.raises(Exception) as exc:
        await client.request(f"{server}/", profile="chrmoe")
    assert "chrmoe" in str(exc.value).lower()


async def test_an_explicit_header_beats_the_profile(server, client):
    r = await client.request(
        f"{server}/echo-headers",
        profile="chrome",
        headers=[("user-agent", "mine/1.0")],
    )
    assert "mine/1.0" in r.text
    assert "Chrome/131" not in r.text


# ── The report ───────────────────────────────────────────────────


async def test_an_ordinary_response_reports_reached(server, client):
    r = await client.request(f"{server}/")
    assert r.conclusion == ("reached", "-")
    assert r.protection == ("ok", "-")
    assert [a[0] for a in r.attempts] == ["modern"]
    assert r.attempts[0][1] == "reached"
    assert r.attempts[0][2] == 200


async def test_a_challenge_asks_for_a_browser(server, client):
    """The signal BBOT keys on. A challenge needs JavaScript, so no amount of
    retrying with different connection settings will help and the URL should
    go to a real browser instead."""
    r = await client.request(f"{server}/cf-challenge")
    assert r.status_code == 403
    assert r.protection == ("challenge", "cloudflare")
    assert r.conclusion == ("needs_browser", "cloudflare")


async def test_a_block_is_not_a_challenge(server, client):
    """The distinction that decides whether to launch a browser. A block might
    yield to a different approach; a challenge will not."""
    r = await client.request(f"{server}/akamai-block")
    assert r.protection == ("blocked", "akamai")
    conclusion, vendor = r.conclusion
    assert conclusion == "blocked"
    assert vendor == "akamai"
    assert conclusion != "needs_browser"


async def test_a_bare_403_names_no_vendor(server, client):
    """Most 403s are ordinary authorization failures. Reporting one as though a
    product refused us would invite a caller to act on nothing, and internally
    it is what stops the ladder spending a second request on every one."""
    r = await client.request(f"{server}/plain-403")
    assert r.protection == ("blocked", "unknown")
    assert r.conclusion == ("blocked", "-")


# ── Failures ─────────────────────────────────────────────────────


async def test_a_refused_connection_is_legible(client):
    """Before 1.0 every transport failure arrived as a RuntimeError whose only
    content was a sentence, so a caller could not tell a dead host from a
    refused cipher without parsing English."""
    with pytest.raises(blasthttp.TransportError) as exc:
        await client.request("http://127.0.0.1:1/", timeout=5)

    e = exc.value
    assert e.kind == "connection"
    assert e.tls_failure is None
    assert e.retryable is True
    assert e.conclusion == "unreachable"


async def test_transport_error_is_still_a_runtime_error(client):
    """Subclassing RuntimeError on purpose, so callers written against the old
    behaviour keep working."""
    with pytest.raises(RuntimeError):
        await client.request("http://127.0.0.1:1/", timeout=5)


async def test_batch_results_carry_the_report(server, client):
    cfgs = [
        blasthttp.BatchConfig(f"{server}/"),
        blasthttp.BatchConfig(f"{server}/cf-challenge"),
    ]
    results = await client.request_batch(cfgs, concurrency=2)
    by_url = {r.url: r for r in results}

    assert by_url[f"{server}/"].response.conclusion == ("reached", "-")
    assert by_url[f"{server}/cf-challenge"].response.conclusion == (
        "needs_browser",
        "cloudflare",
    )
