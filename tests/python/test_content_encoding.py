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


def _raw_deflate(data):
    """Bare deflate, no zlib wrapper (RFC 1951)."""
    c = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return c.compress(data) + c.flush()


# Bodies for the `/ok` route: what to declare, and what to send. Both
# shapes of `deflate` are here because both are in the wild.
# RFC 9110 8.4.1.2 specifies it as a zlib stream (`zlib.compress`), which
# is what IIS and several CDN fronts send, while plenty of other servers
# send the bare deflate stream. Neither decoder can read the other's
# input, so handling only one hands back a compressed body as content.
OK_BODIES = {
    "gzip": ("gzip", gzip.compress(PAYLOAD)),
    "deflate": ("deflate", _raw_deflate(PAYLOAD)),
    "deflate-zlib": ("deflate", zlib.compress(PAYLOAD)),
}
# Bodies the stdlib can produce, for the cases that need a real body.
COMPRESSIBLE = list(OK_BODIES)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self, status, encoding, body, send_body=True):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        if encoding:
            # A list means one header line per entry, which is how an edge
            # that compresses an already-compressed body does it: it adds
            # its own line rather than editing the one underneath.
            for enc in [encoding] if isinstance(encoding, str) else encoding:
                self.send_header("Content-Encoding", enc)
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
            encoding, body = OK_BODIES[arg]
            self._respond(200, encoding, body)
        elif kind == "doubled":
            # Two Content-Encoding lines, both applied. Reading only the
            # first peels one layer and calls the rest a body.
            self._respond(200, ["gzip", "gzip"], gzip.compress(gzip.compress(PAYLOAD)))
        elif kind == "doubled-once":
            # Two lines, compressed once. The misconfig shape: a proxy
            # re-adds the header in front of a backend that already set
            # it, without compressing again.
            self._respond(200, ["gzip", "gzip"], gzip.compress(PAYLOAD))
        elif kind == "doubled-mismatch":
            # Two lines, only the first applied.
            self._respond(200, ["gzip", "br"], gzip.compress(PAYLOAD))
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
        elif kind == "incompressible-plain":
            # No encoding, so the only cap that applies is the one on the
            # wire read.
            self._respond(200, None, INCOMPRESSIBLE)
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
    assert r.decode_error is None


async def test_zlib_wrapped_deflate_is_not_handed_back_compressed(client, server):
    """`Content-Encoding: deflate` is specified as a zlib stream, and only
    raw deflate was handled, so the spec-conformant form came back as
    compressed bytes with nothing to distinguish it from a real body."""
    r = await client.request(f"{server}/ok/deflate-zlib", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == PAYLOAD
    assert r.content != zlib.compress(PAYLOAD)


async def test_repeated_content_encoding_lines_are_all_undone(client, server):
    """Two `Content-Encoding: gzip` lines mean the same thing as one line
    reading `gzip, gzip`. Only the first was read, so one layer came off
    and the still-compressed remainder was returned as the body."""
    r = await client.request(f"{server}/doubled", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == PAYLOAD
    assert r.decode_error is None


async def test_repeated_lines_preserve_both_headers(client, server):
    """Joining the values for decoding must not flatten what arrived. Two
    lines is a front-end/back-end disagreement worth seeing."""
    r = await client.request(f"{server}/doubled", timeout=10, follow_redirects=False)
    encodings = [v for k, v in r.headers.items() if k.lower() == "content-encoding"]
    assert encodings == ["gzip", "gzip"]


async def test_doubled_header_over_a_singly_compressed_body_still_reads(client, server):
    """The other reading of two identical lines, and the more common one:
    the header was added twice but the body was compressed once. One gzip
    comes off and what's left is the body, so keep that rather than
    reverting to the bytes that arrived. Flagged, because the alternative
    reading leaves a layer on and the two are indistinguishable."""
    r = await client.request(f"{server}/doubled-once", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == PAYLOAD
    assert "1 of 2 content-encoding layers came off" in r.decode_error


async def test_repeated_lines_that_were_not_all_applied_are_flagged(client, server):
    """Declares gzip and br on separate lines but only applied gzip. Same
    as the single-line case: keep the response, hand back what arrived,
    and say the body isn't decoded."""
    r = await client.request(f"{server}/doubled-mismatch", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    # br is the outermost coding and was never applied, so nothing came
    # off and the caller gets exactly what arrived.
    assert r.content == gzip.compress(PAYLOAD)
    assert r.decode_error is not None


async def test_x_gzip_alias_is_decompressed(client, server):
    """Treating the alias as unknown handed back compressed bytes as if
    they were the body."""
    r = await client.request(f"{server}/alias", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == PAYLOAD


async def test_unknown_encoding_returns_the_body_untouched(client, server):
    """Nothing to undo it with, so don't pretend. The caller gets the
    bytes exactly as they arrived, and `decode_error` names the coding."""
    r = await client.request(f"{server}/unknown", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == gzip.compress(PAYLOAD)
    assert "magic-codec" in r.decode_error


async def test_body_that_is_not_actually_compressed_is_returned_raw(client, server):
    """Nothing inflates, but the status and headers arrived fine and these
    are the bytes the server really sent. Dropping the response would look
    exactly like an unreachable host and lose far more than it saves."""
    r = await client.request(f"{server}/garbage", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == b"this is not compressed"
    assert "decompression failed" in r.decode_error


async def test_declared_stack_that_was_not_applied_is_returned_raw(client, server):
    """Declares `gzip, br` but only gzip was applied, so brotli finds no
    stream. Same reasoning: keep the response, hand back what arrived."""
    r = await client.request(f"{server}/mismatch", timeout=10, follow_redirects=False)
    assert r.status_code == 200
    assert r.content == gzip.compress(PAYLOAD)
    assert r.decode_error is not None


async def test_decode_error_is_none_when_there_is_no_encoding(client, server):
    """The flag only speaks up when `content` isn't content. A plain
    response has nothing to report."""
    r = await client.request(f"{server}/nothing-here", timeout=10, follow_redirects=False)
    assert r.status_code == 404
    assert r.decode_error is None


async def test_max_body_size_truncating_a_compressed_stream(client, server):
    """`max_body_size` cuts the compressed bytes, so the stream ends
    mid-way. Keep what inflated instead of discarding the response, and
    say that it isn't whole."""
    cap = 10_000
    r = await client.request(f"{server}/incompressible", timeout=20, follow_redirects=False, max_body_size=cap)
    assert r.status_code == 200
    # Genuinely partial: something inflated, but less than the whole body
    # and short of the cap, which is what a broken stream looks like.
    assert 0 < len(r.content) <= cap
    assert len(r.content) < len(INCOMPRESSIBLE)
    assert INCOMPRESSIBLE.startswith(r.content)
    # The bytes read like an ordinary body and aren't one, so the flag has
    # to carry that. Without this assertion the test passes either way.
    assert r.decode_error is not None
    assert "did not decode cleanly" in r.decode_error


async def test_max_body_size_too_small_to_inflate_anything(client, server):
    """A 2-byte cap doesn't even cover the gzip header, so nothing
    inflates. The response survives with the bytes that did arrive, and
    says why they aren't content."""
    r = await client.request(f"{server}/ok/gzip", timeout=10, follow_redirects=False, max_body_size=2)
    assert r.status_code == 200
    assert r.content == gzip.compress(PAYLOAD)[:2]
    assert "max_body cap" in r.decode_error


async def test_max_body_size_bounds_the_decompressed_body(client, server):
    """The cap has to apply to inflated output, not just wire bytes,
    or a small response can inflate into an unbounded allocation."""
    r = await client.request(f"{server}/big", timeout=20, follow_redirects=False, max_body_size=50_000)
    assert r.status_code == 200
    assert len(r.content) == 50_000


async def test_max_body_size_bounds_the_wire_read(client, server):
    """Exercises the streaming read against a real server: the cap stops
    the read partway through a body the server is still writing, which
    means abandoning the connection. That the read actually stops early,
    rather than buffering and slicing, is pinned in the Rust unit tests
    where the frames can be counted."""
    r = await client.request(f"{server}/incompressible-plain", timeout=20, follow_redirects=False, max_body_size=1000)
    assert r.status_code == 200
    assert r.content == INCOMPRESSIBLE[:1000]


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
