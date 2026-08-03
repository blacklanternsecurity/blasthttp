"""End-to-end tests for response body decompression.

The interesting cases are the ones where the body doesn't match what
`Content-Encoding` promises. A response whose status and headers arrived
cleanly should survive that, because throwing it away leaves the caller
unable to tell a live host from an unreachable one.

Codec-level cases live in the Rust unit tests for `decompress()`, since
there is no brotli compressor in the Python test environment and
anything needing real `br` input has to be covered there instead. The
empty-body cases below cover all three codecs, because they need no
compressor at all.
"""

import gzip
import os
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import blasthttp
import pytest

PAYLOAD = b"<html><body>hello</body></html>"

# Incompressible, so the gzip stream is about the same size as the body it
# carries. That is what makes partial recovery observable: a cap that cuts
# the stream leaves output below the cap rather than hitting it cleanly.
INCOMPRESSIBLE = os.urandom(200_000)

# Codecs blasthttp requests by default. `deflate` already tolerated an
# empty body before the fix; gzip and br did not.
ALL_ENCODINGS = ["gzip", "deflate", "br"]
# Codecs the stdlib can produce, for the cases that need a real body.
COMPRESSIBLE = ["gzip", "deflate"]


def _compress(encoding, data):
    if encoding == "gzip":
        return gzip.compress(data)
    if encoding == "deflate":
        # Raw deflate, which is what blasthttp's DeflateDecoder expects.
        c = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        return c.compress(data) + c.flush()
    raise AssertionError(f"no stdlib compressor for {encoding}")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self, status, encoding, body, send_body=True):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def do_HEAD(self):
        # A HEAD response carries the entity headers of the GET it
        # mirrors, including Content-Encoding, but never a body.
        enc = self.path.lstrip("/") or "gzip"
        self._respond(200, enc, b"", send_body=False)

    def do_GET(self):
        kind, _, arg = self.path.lstrip("/").partition("/")

        if kind == "empty":
            # Declared encoding, zero-length body. Every bodyless
            # redirect from an edge that adds Content-Encoding looks
            # like this.
            self._respond(302, arg, b"")
        elif kind == "notmodified":
            self.send_response(304)
            self.send_header("Content-Encoding", arg)
            self.end_headers()
        elif kind == "ok":
            self._respond(200, arg, _compress(arg, PAYLOAD))
        elif kind == "alias":
            # `x-gzip` is a deprecated alias for `gzip`, still seen.
            self._respond(200, "x-gzip", gzip.compress(PAYLOAD))
        elif kind == "unknown":
            # A coding we can't undo. The body comes back untouched
            # rather than half-decoded into nonsense.
            self._respond(200, "magic-codec", gzip.compress(PAYLOAD))
        elif kind == "garbage":
            # Declared gzip, body that has no gzip header at all.
            self._respond(200, "gzip", b"this is not compressed")
        elif kind == "mismatch":
            # Declares two codings but only applied one.
            self._respond(200, "gzip, br", gzip.compress(PAYLOAD))
        elif kind == "incompressible":
            self._respond(200, "gzip", gzip.compress(INCOMPRESSIBLE))
        elif kind == "big":
            # ~5KB on the wire, 5MB inflated: only a bound on the output
            # makes a cap below that mean anything.
            self._respond(200, "gzip", gzip.compress(b"\x00" * 5_000_000))
        else:
            self._respond(404, None, b"")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def client():
    return blasthttp.BlastHTTP()


@pytest.mark.parametrize("encoding", ALL_ENCODINGS)
async def test_declared_encoding_with_empty_body(client, server, encoding):
    """A 302 that declares an encoding but carries no body is still a
    302. gzip and br used to raise here and the response was lost."""
    r = await client.request(f"{server}/empty/{encoding}", timeout=10, follow_redirects=False)
    assert r.status_code == 302
    assert r.content == b""


@pytest.mark.parametrize("encoding", ALL_ENCODINGS)
async def test_head_with_declared_encoding(client, server, encoding):
    """HEAD echoes the GET's Content-Encoding with no body, which is
    required behavior rather than a broken server."""
    r = await client.request(f"{server}/{encoding}", method="HEAD", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == b""


@pytest.mark.parametrize("encoding", ALL_ENCODINGS)
async def test_304_with_declared_encoding(client, server, encoding):
    """A 304 carries the representation headers a 200 would, and no body."""
    r = await client.request(f"{server}/notmodified/{encoding}", timeout=10, follow_redirects=False)
    assert r.status_code == 304
    assert r.content == b""


@pytest.mark.parametrize("encoding", COMPRESSIBLE)
async def test_normal_compressed_body_still_decompresses(client, server, encoding):
    """The ordinary path is unaffected."""
    r = await client.request(f"{server}/ok/{encoding}", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == PAYLOAD


async def test_x_gzip_alias_is_decompressed(client, server):
    """Treating the alias as unknown handed back compressed bytes as if
    they were the body."""
    r = await client.request(f"{server}/alias", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == PAYLOAD


async def test_unknown_encoding_returns_the_body_untouched(client, server):
    """Nothing to undo it with, so don't pretend. The caller gets the
    bytes exactly as they arrived."""
    r = await client.request(f"{server}/unknown", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == gzip.compress(PAYLOAD)


async def test_body_that_is_not_actually_compressed_is_returned_raw(client, server):
    """Nothing inflates, but the status and headers arrived fine and these
    are the bytes the server really sent. Dropping the response would look
    exactly like an unreachable host and lose far more than it saves."""
    r = await client.request(f"{server}/garbage", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == b"this is not compressed"


async def test_declared_stack_that_was_not_applied_is_returned_raw(client, server):
    """Declares `gzip, br` but only gzip was applied, so brotli finds no
    stream. Same reasoning: keep the response, hand back what arrived."""
    r = await client.request(f"{server}/mismatch", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == gzip.compress(PAYLOAD)


async def test_max_body_size_truncating_a_compressed_stream(client, server):
    """`max_body_size` cuts the compressed bytes, so the stream ends
    mid-way. Keep what inflated instead of discarding the response."""
    cap = 10_000
    r = await client.request(f"{server}/incompressible", timeout=20, follow_redirects=False, max_body_size=cap)
    assert r.status_code == 200
    # Genuinely partial: something inflated, but less than the whole body
    # and short of the cap, which is what a broken stream looks like.
    assert 0 < len(r.content) <= cap
    assert len(r.content) < len(INCOMPRESSIBLE)
    assert INCOMPRESSIBLE.startswith(r.content)


async def test_max_body_size_too_small_to_inflate_anything(client, server):
    """A 2-byte cap doesn't even cover the gzip header, so nothing
    inflates. The response survives with the bytes that did arrive."""
    r = await client.request(f"{server}/ok/gzip", timeout=10, follow_redirects=False, max_body_size=2)
    assert r.status_code == 200
    assert r.content == gzip.compress(PAYLOAD)[:2]


async def test_max_body_size_bounds_the_decompressed_body(client, server):
    """The cap has to apply to inflated output, not just wire bytes,
    or a small response can inflate into an unbounded allocation."""
    r = await client.request(f"{server}/big", timeout=20, follow_redirects=False, max_body_size=50_000)
    assert r.status_code == 200
    assert len(r.content) == 50_000


async def test_empty_body_in_batch(client, server):
    """The batch paths share `parse_response`, so they need the same
    guarantee as `request()`."""
    configs = [blasthttp.BatchConfig(f"{server}/empty/{e}", timeout=10, follow_redirects=False) for e in ALL_ENCODINGS]
    results = await client.request_batch(configs, concurrency=len(configs))
    assert len(results) == len(ALL_ENCODINGS)
    for r in results:
        assert r.error is None, r.error
        assert r.response.status_code == 302
        assert r.response.content == b""
