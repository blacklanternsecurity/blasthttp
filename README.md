# blasthttp

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-black.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust 2024](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Crates.io](https://img.shields.io/crates/v/blasthttp.svg?color=orange)](https://crates.io/crates/blasthttp)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/blasthttp.svg?color=blue)](https://pypi.org/project/blasthttp/)
[![Rust Tests](https://github.com/blacklanternsecurity/blasthttp/actions/workflows/rust-tests.yml/badge.svg)](https://github.com/blacklanternsecurity/blasthttp/actions/workflows/rust-tests.yml)
[![Python Tests](https://github.com/blacklanternsecurity/blasthttp/actions/workflows/python-tests.yml/badge.svg)](https://github.com/blacklanternsecurity/blasthttp/actions/workflows/python-tests.yml)

Offensive-first HTTP library written in Rust with Python bindings. Built for [BBOT](https://github.com/blacklanternsecurity/bbot).

## Installation

```bash
# Python
pip install blasthttp

# Rust
cargo add blasthttp
```

## Key Advantages

- **Batch connection reuse** — connections are pooled and reused within a batch, dramatically reducing overhead when scanning many URLs on the same hosts
- **Rust performance** — async I/O, zero-copy where possible, and native concurrency give significant speed improvements over pure Python HTTP clients
- **SSL cert info on every request** — extracts CN, SANs, emails, issuer, validity dates, and fingerprint during the TLS handshake that's already happening, eliminating the need for a separate connection to gather this information
- **All TLS ciphers available by default** — custom-compiled OpenSSL 3.3.2 with legacy provider baked in (RC4, 3DES, export ciphers, SSLv3) so you can connect to anything
- **No cert validation by default** — offensive-first: connects to self-signed, expired, and misconfigured TLS without extra config
- **HTTP/2 support** — automatic via ALPN negotiation, falls back to HTTP/1.1
- **Low-level primitives** — `RawConnection` for byte-level TCP/TLS I/O (bypasses HTTP framing entirely) and `blasthttp.h2` for manual H2 frame construction (includes a permissive HPACK encoder that emits bytes a strict encoder refuses, the building block for H2 smuggling / CRLF-injection tooling)
- **Response hashing built-in** — MD5, SHA256, and MurmurHash3 computed in Rust for both body and headers, ready for fingerprinting

## CLI Usage

```bash
# Single request
blasthttp https://example.com

# POST with headers and body
blasthttp https://example.com -X POST -H "Content-Type: application/json" -d '{"key":"value"}'

# Batch mode — read URLs from a file, 100 concurrent
blasthttp -l urls.txt -c 100

# Follow redirects
blasthttp https://example.com -L

# Through a proxy
blasthttp https://example.com -x http://127.0.0.1:8080

# ...but connect directly to certain hosts (host, *.suffix, IP, or CIDR)
blasthttp https://example.com -x http://127.0.0.1:8080 --no-proxy '*.internal.corp' --no-proxy 10.0.0.0/8

# Force specific TLS versions/ciphers
blasthttp https://legacy-server.com --min-tls 1.0 --ciphers "RC4-SHA"

# Verbose output (pretty JSON + debug info, -vv includes body)
blasthttp https://example.com -v
```

Output is JSON (one object per response), including status, headers, redirect chain with per-hop peer IP, TLS cert info, content hashes, parsed cookies, and the actual TCP peer IP for the final hop:

```json
{
  "url": "https://example.com/",
  "status": 200,
  "request_url": "https://example.com",
  "request_method": "GET",
  "headers": [["content-type", "text/html"], ...],
  "raw_headers": "content-type: text/html\r\n...",
  "body": "<!doctype html>...",
  "cookies": {"session": "abc123"},
  "elapsed_ms": 120,
  "peer_ip": "93.184.215.14",
  "redirect_chain": [
    {"url": "http://example.com/", "status": 301, "peer_ip": "93.184.215.14"}
  ],
  "cert_info": {
    "common_name": "example.com",
    "sans": ["example.com", "www.example.com"],
    "emails": [],
    "issuer": "DigiCert Global G2",
    "not_before": "2024-01-15T00:00:00Z",
    "not_after": "2025-02-15T23:59:59Z",
    "fingerprint_sha256": "a0b1c2..."
  },
  "hash": {
    "body_md5": "...",
    "body_mmh3": 1234567,
    "body_sha256": "...",
    "header_md5": "...",
    "header_mmh3": -987654,
    "header_sha256": "..."
  }
}
```

### Options

| Flag | Description | Default |
|---|---|---|
| `URL` | Target URL (omit when using `-l`) | |
| `-X, --method` | HTTP method | `GET` |
| `-H, --header` | Custom header (repeatable) | |
| `-d, --data` | Request body | |
| `-l, --list` | File of URLs for batch mode | |
| `-c, --concurrency` | Max concurrent requests (batch) | `50` |
| `--rate-limit` | Requests per second (batch mode) | unlimited |
| `-L, --follow-redirects` | Follow redirects | off |
| `--max-redirects` | Max redirect hops | `10` |
| `--no-redirect-cookies` | Don't apply cookies a redirect sets to later hops | off |
| `-t, --timeout` | Request timeout (seconds) | `10` |
| `--max-body-size` | Max response body (bytes) | 10 MB |
| `--verify` | Enable TLS cert validation | off |
| `-x, --proxy` | HTTP/SOCKS proxy URL | |
| `--no-proxy` | Host that bypasses the proxy: `host`, `*.suffix`, IP, CIDR, or `*` (repeatable) | |
| `--ciphers` | OpenSSL cipher string | all |
| `--min-tls` | Minimum TLS version (1.0–1.3) | |
| `--max-tls` | Maximum TLS version (1.0–1.3) | |
| `-v, --verbose` | Verbose output (-vv includes body) | |

## Python API

All request methods are async — they return native Python coroutines via `pyo3-async-runtimes`.

```python
import asyncio
import blasthttp

async def main():
    client = blasthttp.BlastHTTP()

    # Single request — Response is httpx-style
    r = await client.request("https://example.com")
    print(r.status_code, r.is_success)            # 200, True
    print(r.headers["Content-Type"])              # case-insensitive
    print(r.peer_ip)                              # actual TCP peer IP
    print(r.text[:80])                            # UTF-8 body (lazy)
    print(r.hash.body_md5)                        # md5/sha256/mmh3 (lazy)
    print(r.cookies)                              # Set-Cookie parsed (lazy)
    print(r.request.url, r.request.method)        # original (pre-redirect)
    r.raise_for_status()                          # raises HTTPStatusError on 4xx/5xx

    # Batch requests — full result list at the end
    configs = [
        blasthttp.BatchConfig("https://a.com"),
        blasthttp.BatchConfig("https://b.com", method="POST", body="data"),
    ]
    results = await client.request_batch(configs, concurrency=50)
    for r in results:
        if r.success:
            print(r.url, r.response.status_code, r.response.peer_ip)

    # Streaming batch — process results as they complete
    async for batch in client.request_batch_stream(configs, concurrency=50):
        for r in batch:
            if r.success:
                print(r.url, r.response.status_code)

    # Download to file
    await client.download("https://example.com/file.zip", "/tmp/file.zip")

asyncio.run(main())
```

### Response API

`Response` follows the httpx convention so it works as a drop-in for httpx-flavored consumers:

| Attribute | Type | Notes |
|---|---|---|
| `status` / `status_code` | `int` | HTTP status code |
| `is_success` | `bool` | `True` for 2xx-3xx |
| `url` | `str` | final URL (after redirects) |
| `text` / `body` | `str` | UTF-8 decoded body (lazy) |
| `content` / `body_bytes` | `bytes` | raw body |
| `headers` | `Headers` | case-insensitive, mutable; `headers["Content-Type"]` works either case |
| `cookies` | `dict[str, str]` | parsed `Set-Cookie` (lazy) |
| `raw_headers` | `str` | canonical `Name: Value\r\n…` form (lazy) |
| `hash` | `ResponseHash` | md5 / sha256 / mmh3 of body and headers (lazy) |
| `cert_info` | `CertInfo \| None` | TLS cert details from the handshake |
| `peer_ip` | `str \| None` | actual IP of the final hop's TCP connection; `None` when proxied |
| `redirect_chain` | `list[RedirectHop]` | each hop carries its own `peer_ip` |
| `elapsed_ms` / `elapsed` | `int` / `timedelta` | total request time |
| `request` | `Request` | original `request.url` and `request.method` |
| `debug_log` | `list[str]` | internal debug/timing lines |
| `decode_error` | `str \| None` | why `content` is not decoded content; `None` on any ordinary response |
| `json()` | callable | `json.loads(self.text)` |
| `raise_for_status()` | callable | raises `HTTPStatusError` on 4xx/5xx |

`body`, `raw_headers`, `cookies`, and `hash` are lazy — first access computes, subsequent accesses are free. Hashing a 10 MB body is real work; batch jobs that filter on `status` and never look at the body don't pay for it.

A response whose body won't decode is still returned: the status line and headers arrived cleanly, and losing the response looks the same to the caller as an unreachable host. When that happens `decode_error` says why, and how far decoding got. It's also set when a stream decodes partway and then reports damage or an early end, since those bytes read like an ordinary body and aren't one. With nothing undone, `content` is exactly what the server sent. With a stack of codings only partly undone, `content` is as far in as decoding reached, which is usually the body, since a header that overstates the codings (a proxy re-adding `Content-Encoding: gzip` in front of a backend that already set it) is more common than a body really encoded that many times. Anything that hashes, matches, or diffs bodies should check it, since encoded bytes are otherwise indistinguishable from content.

`decode_error` is also set when `max_body` cuts a compressed body short. The cap bounds both what is read off the wire and what the decoder keeps, so which limit trips first depends on how well the body compresses: a highly compressible body fills the output cap and comes back as clean content, while a near-incompressible one has its wire bytes cut mid-stream and is flagged. That is deliberate, since a truncated prefix is exactly what a middlebox cutting a response produces. Code filtering on `decode_error is None` will drop capped incompressible bodies it would otherwise have kept.

`headers` is a `Headers` instance (case-insensitive view), not a list of tuples. Iterate with `.items()` to get `(name, value)` pairs preserving original case and duplicate names (e.g. multiple `Set-Cookie`). `Headers` is registered with `collections.abc.MutableMapping`, so libraries that special-case mappings (`DeepDiff`, `dataclasses`, etc.) recognize it.

`raise_for_status()` raises `blasthttp.HTTPStatusError` on 4xx/5xx — import it directly:

```python
from blasthttp import HTTPStatusError
try:
    r = await client.request("https://example.com/404")
    r.raise_for_status()
except HTTPStatusError as e:
    print(e.response.status_code)   # the failing Response is attached
```

`Response`, `BatchResult`, `RedirectHop`, and `Headers` all have Python constructors so test code can synthesize them from canned data — `blasthttp.Response(url=..., status=200, headers=[...], body=b"...", ...)`. Useful when building fixtures by hand; the `blasthttp.mock` submodule below uses them under the hood.

### Batch vs. streaming batch

Two ways to issue the same workload — pick whichever matches how you want to consume the results:

| | Returns | Consume with | When to use |
|---|---|---|---|
| `request_batch(configs, ...)` | `list[BatchResult]` after every request finishes | `results = await ...; for r in results:` | You want the full set in one shot. |
| `request_batch_stream(configs, ...)` | async iterator of `list[BatchResult]` chunks, in completion order | `async for batch in ...: for r in batch:` | A slow request shouldn't block faster peers behind it; you want to overlap consumer work with in-flight HTTP I/O; partial results are useful before the slowest finishes. |

`request_batch_stream` yields up to 1000 results per chunk, or whatever has accumulated after ~200ms — the timeout flushes partial chunks so the consumer is never starved when results trickle in slowly. Both functions accept the same `(configs, concurrency=50, rate_limit=None)` arguments and respect `set_rate_limit()` identically.

### `request()` parameters

All parameters except `url` are optional:

| Parameter | Type | Notes |
|---|---|---|
| `url` | `str` | Target URL |
| `method` | `str` | HTTP method (default `GET`) |
| `headers` | `list[tuple[str, str]]` | Request headers |
| `body` | `str \| bytes` | Request body (mutually exclusive with `files`) |
| `files` | `dict` | Multipart form-data (httpx-style `files=`; see below) |
| `timeout` | `int` | Request timeout in seconds |
| `follow_redirects` | `bool` | Follow redirects |
| `max_redirects` | `int` | Max redirect hops |
| `redirect_cookies` | `bool` | Apply cookies a redirect sets to later hops (default `True`) |
| `verify_certs` | `bool` | Enable TLS cert validation (default `False`) |
| `proxy` | `str` | HTTP/SOCKS proxy URL |
| `no_proxy` | `list[str]` | Hosts that bypass the proxy |
| `cipher_string` | `str` | OpenSSL cipher string |
| `min_tls_version` | `str` | Minimum TLS version (`"1.0"`–`"1.3"`) |
| `max_tls_version` | `str` | Maximum TLS version (`"1.0"`–`"1.3"`) |
| `retries` | `int` | Number of retries on failure |
| `retry_wait_min_ms` | `int` | Minimum backoff between retries (ms) |
| `retry_wait_max_ms` | `int` | Maximum backoff between retries (ms) |
| `max_body_size` | `int` | Max response body bytes to read; stops the read, not just what's kept |
| `request_target` | `str` | Override the HTTP request-line URI |
| `resolve_ip` | `str` | Connect to this IP (DNS pinning / `curl --resolve`) |
| `alpn_protocols` | `list[str]` | ALPN list to offer; the request is spoken over whatever the server picks |

`BatchConfig` accepts the same parameters (pass them as constructor kwargs).

`alpn_protocols` defaults differ by path, because the offer is part of the client's TLS fingerprint and changing it changes how existing callers look on the wire. Ordinary pooled requests offer `["h2", "http/1.1"]`; requests with `resolve_ip` or `request_target` set bypass the pool and offer `["http/1.1"]` alone. Pass `["http/1.1"]` to keep a request off HTTP/2, or `["h2"]` to force it. `request_target` can't be combined with an HTTP/2 offer, since h2 carries the target in `:path` rather than a request-line — use `raw_connect` with `blasthttp.h2` for that.

### Multipart file uploads

Pass `files` to `request()` or `BatchConfig` for httpx-style multipart form-data. `body` and `files` are mutually exclusive — passing both raises `ValueError`.

```python
r = await client.request(
    "https://example.com/upload",
    method="POST",
    files={"document": ("report.pdf", pdf_bytes, "application/pdf")},
)
```

The `Content-Type: multipart/form-data` boundary header is set automatically.

### Retries

`request()`, `download()`, and `BatchConfig` support automatic retries with exponential backoff:

```python
r = await client.request(
    "https://flaky-api.example.com/data",
    retries=3,
    retry_wait_min_ms=100,
    retry_wait_max_ms=5000,
)
```

### `download()` parameters

`download(url, path, ...)` saves a response body to a file. It always follows redirects (up to 10 hops).

| Parameter | Type | Notes |
|---|---|---|
| `url` | `str` | Target URL |
| `path` | `str` | Local file path to write |
| `max_size` | `int` | Max response body bytes |
| `timeout` | `int` | Request timeout in seconds |
| `verify_certs` | `bool` | Enable TLS cert validation |
| `proxy` | `str` | HTTP/SOCKS proxy URL |
| `no_proxy` | `list[str]` | Hosts that bypass the proxy |
| `headers` | `list[tuple[str, str]]` | Request headers |
| `retries` | `int` | Number of retries on failure |

### DNS Pinning & Request-Line Control

Use `resolve_ip` to connect to a specific IP while keeping the original hostname for SNI and Host header — like `curl --resolve`:

```python
# Connect to 93.184.215.14 but use example.com for TLS SNI and Host header
response = await client.request("https://example.com/", resolve_ip="93.184.215.14")

# Virtual host scanning: override Host header while pinning to target IP
response = await client.request(
    "http://target.com/",
    headers=[("Host", "secret-vhost.target.com")],
    resolve_ip="10.0.0.1",
)
```

Use `request_target` to override the request-line URI (e.g. for SSRF testing or request smuggling):

```python
# Send "GET http://internal.server/admin HTTP/1.1" on the wire
response = await client.request(
    "http://proxy.target.com/",
    request_target="http://internal.server/admin",
)
```

### Cookies across redirects

When `follow_redirects` is on, a cookie set by one hop is sent on the hops that follow it, the same way a browser does. That's what makes a login or bot-check page work: it hands you a cookie along with the redirect, and the cookie has to be on the next request to count for anything. Without this you'd loop or land back on the same page.

This is **not a session**, and there's no cookie storage behind it. What a chain collects is created when the request starts and dropped when it returns, so nothing carries into the next request and no two requests can see each other's cookies. A batch of 500 URLs runs 500 independent chains, which keeps every result reproducible on its own.

What a chain will hold is capped, since a response can set as many cookies as it likes and every later hop would carry all of them: 4096 bytes per cookie and 50 cookies, which is what RFC 6265 asks a client to support and roughly what browsers allow, and 8KB across the whole chain, which is about where servers stop accepting a header line. Past those, later cookies are dropped and the ones already held are kept, with a line in the debug log saying what went.

Which cookie goes to which hop follows the usual rules (RFC 6265): a cookie with no `Domain` goes back only to the exact host that set it, a `Domain` that doesn't cover the host that sent it is thrown out, `Path` has to match, and `Secure` cookies never go over plain HTTP.

`Domain` also gets checked against the Public Suffix List, because the rules above don't cover it on their own: `Domain=com` does cover the host that set it, so it passes every other check, and then covers every other `.com` the chain visits. A cookie may only widen within one registrable domain, so `auth.example.com` can hand one to `app.example.com`, while `Domain=com`, `Domain=co.uk`, `Domain=github.io` and `Domain=s3.amazonaws.com` are refused. That is what stops a redirect walking a cookie the chain picked up onto an unrelated host. Headers you supply yourself are a different matter: those are sent as given on every hop, including after a redirect to another host, because a header you set is a header we send.

Pass `redirect_cookies=False` (or `--no-redirect-cookies` on the CLI) to turn it off and send only your own headers on every hop.

```python
# On by default.
r = await client.request("https://example.com/login", method="POST",
                         body="user=x&pass=y", follow_redirects=True)

# Off: every hop gets only the headers you supplied.
r = await client.request("https://example.com/login", follow_redirects=True,
                         redirect_cookies=False)
```

**A cookie you set yourself always wins.** If your request carries `Cookie: session=mine`, every hop of that chain sends `session=mine`. A `Set-Cookie` naming a cookie you set is ignored: it can't replace your value, an expiry on it can't delete your value, and the two never go out together as a duplicate pair. Sites reset cookies mid-redirect routinely, and servers disagree about which value to read when a name appears twice (some take the first, some the last), so the only rule that behaves the same everywhere is that what you wrote is what lands on the wire. Cookies the chain sets under *other* names are merged into your `Cookie` header, yours first.

```python
# Every hop sends session=mine, whatever the site tries to set.
r = await client.request("https://example.com/start", follow_redirects=True,
                         headers=[("Cookie", "session=mine")])
```

Run with `-v` to see it happen: the debug log records both the cookies each hop is given and any `Set-Cookie` that lost to one of yours.

### Proxy exclusions (`no_proxy`)

`proxy` routes a request through an HTTP or SOCKS5 proxy; `no_proxy` is a per-request list of hosts that bypass it and connect directly — the `NO_PROXY` equivalent. It's accepted by `request()`, `download()`, `raw_connect()`, and `BatchConfig`, and as the repeatable `--no-proxy` CLI flag.

```python
# Proxy everything except internal hosts and the loopback range.
r = await client.request(
    "https://example.com/",
    proxy="http://127.0.0.1:8080",
    no_proxy=["localhost", "*.internal.corp", "10.0.0.0/8"],
)
```

Each entry matches case-insensitively as:

- an exact hostname (`elastic.corp`);
- a domain suffix — `*.corp`, `.corp`, and `corp` are equivalent and match the domain itself plus any subdomain;
- a single IP (`127.0.0.1`, `::1`);
- a CIDR range (`10.0.0.0/8`, `fd00::/8`), matched only against IP hosts;
- or `*` to bypass the proxy for every host.

The proxy/`no_proxy` decision is re-evaluated on **every redirect hop**, not just the first URL: if a request starts on an excluded (direct) host and is redirected onto a non-excluded host, the later hop goes through the proxy — and vice versa.

`no_proxy` only does anything when a `proxy` is set, so passing it without one is rejected up front (the request errors rather than silently ignoring the exclusions).

### Global Rate Limiting

Set a client-level rate limit (requests per second) that applies to **all** request methods — `request()`, `request_batch()`, `request_batch_stream()`, and `download()`:

```python
client = blasthttp.BlastHTTP()
client.set_rate_limit(50)  # 50 requests/sec across all callers

# All of these respect the 50 rps limit:
await client.request("https://example.com")
await client.request_batch(configs, concurrency=100)
await client.download("https://example.com/file", "/tmp/file")

# Disable rate limiting
client.set_rate_limit(0)
# or
client.set_rate_limit(None)
```

When multiple callers share the same `BlastHTTP` instance, the rate limiter is global — two concurrent `request_batch()` (or `request_batch_stream()`) calls will collectively stay under the limit.

The client-level rate limit takes precedence over the per-call `rate_limit` parameter on `request_batch()` / `request_batch_stream()`.

`RawConnection` handles returned from `raw_connect()` inherit the client's rate limiter: every `send_bytes` / `read_raw` call on that handle also consumes one token, so a caller that pipelines many ops on a single connection can't burst past the limit.

### RawConnection — byte-level TCP/TLS I/O

`raw_connect()` returns a `RawConnection` handle that exposes the TCP or TLS stream directly. No HTTP parsing, no framing, no re-emission — you write bytes in and read bytes out. Use it to send hand-crafted requests (malformed HTTP/1, raw HTTP/2 frames, non-HTTP protocols) or to peek at raw server responses the way a protocol fuzzer or smuggling detector needs.

```python
import asyncio
import blasthttp

async def main():
    client = blasthttp.BlastHTTP()

    # Open a TLS connection, negotiating h2 via ALPN.
    conn = await client.raw_connect(
        "https://example.com/",
        alpn_protocols=["h2", "http/1.1"],
    )
    print("ALPN negotiated:", conn.negotiated_alpn)
    print("TLS cert CN:", conn.cert_info.common_name if conn.cert_info else None)

    # Send arbitrary bytes — no Content-Length / framing added for you.
    await conn.send_bytes(
        b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    )

    # Read with a per-call deadline. Empty bytes = timeout or peer close.
    data = await conn.read_raw(max_bytes=65536, timeout_ms=2000)
    print(data[:200])

    await conn.close()

asyncio.run(main())
```

`raw_connect()` takes all the same TLS knobs as `request()` — `verify_certs`, `cipher_string`, `min_tls_version`, `max_tls_version`, `resolve_ip`, `proxy`, `no_proxy`. `alpn_protocols` is a list of byte-strings (commonly `["h2", "http/1.1"]`) used in the TLS ALPN extension. After the handshake, `conn.negotiated_alpn` reports which one the server picked (or `None` if no ALPN was negotiated, including all plain-HTTP connections).

`conn.peer_ip` returns the actual IP address the OS connected to, same as `Response.peer_ip`. `None` when the connection went through a proxy.

### HTTP/2 primitives — `blasthttp.h2`

`blasthttp.h2` is a minimal, **permissive** HTTP/2 toolkit for callers who need to emit custom H2 frames over a `RawConnection`. The encoder deliberately lets you produce bytes a strict implementation refuses (CRLF in header values, invalid header names, forced Huffman on/off, custom indexing choices) — the exact knobs protocol fuzzers and H2 smuggling detectors depend on.

```python
from blasthttp import h2

# Encode a header block with HPACK.
block = h2.encode_headers([
    h2.Header(":method", "GET"),
    h2.Header(":path", "/"),
    h2.Header(":authority", "example.com"),
    h2.Header(":scheme", "https"),
    # Permissive escape hatch: emit CRLF inside a value for
    # CRLF-injection testing against H2-to-H1 downgrades.
    h2.Header(
        "x-injected", "bogus\r\nX-Smuggled: yes",
        allow_invalid_value=True, huffman_value=False,
    ),
])

# Build a full probe: preface + SETTINGS + HEADERS (+ optional DATA).
probe = h2.build_probe(
    [
        h2.Header(":method", "POST"),
        h2.Header(":path", "/"),
        h2.Header(":authority", "example.com"),
        h2.Header(":scheme", "https"),
        h2.Header("content-length", "5"),
    ],
    body=b"hello",
)

# Or assemble frames individually for finer control.
settings = h2.build_settings_frame()
headers = h2.build_headers_frame(block, stream_id=1, end_stream=False)
data = h2.build_data_frame(b"hello", stream_id=1, end_stream=True)

# Decode response frames with a stateful decoder (tracks HPACK
# dynamic-table state across calls).
dec = h2.Decoder()
response_headers = dec.decode(block)  # -> [(name: bytes, value: bytes), ...]
```

`blasthttp.h2` exposes:

- `Header(name, value, **permissiveness)` — a single header-field pair, with flags like `allow_invalid_name`, `allow_invalid_value`, `huffman_name`, `huffman_value`, `indexing`, `force_static_index`, `length_bloat_name`, `length_bloat_value`
- `encode_headers(headers) -> bytes` — HPACK header-block-fragment
- `Decoder()` — stateful HPACK decoder (dynamic-table-aware); `decode(block) -> [(name, value), ...]`
- `build_settings_frame(settings=None, ack=False)`, `build_headers_frame(block, stream_id, end_stream, end_headers, ...)`, `build_data_frame(data, stream_id, end_stream, ...)`, `build_continuation_frame`, `build_rst_stream_frame`, `build_goaway_frame`, `build_ping_frame`, `build_priority_frame`, `build_window_update_frame`, `build_raw_frame` (escape hatch for malformed frames)
- `build_probe(headers, body=None, ...)` — one-shot preface + SETTINGS + HEADERS + optional DATA builder with every knob from the underlying Rust `ProbeOpts` exposed as a keyword argument
- `PREFACE` — the H2 connection preface bytes
- Frame-type + flag constants: `FRAME_HEADERS`, `FRAME_DATA`, `FRAME_SETTINGS`, `FRAME_CONTINUATION`, `FRAME_RST_STREAM`, `FRAME_GOAWAY`, `FRAME_PING`, `FRAME_PRIORITY`, `FRAME_WINDOW_UPDATE`, `FLAG_END_HEADERS`, `FLAG_END_STREAM`, `FLAG_ACK`, `FLAG_PADDED`, `FLAG_PRIORITY`

This isn't a full H2 client — no stream state machine, no flow control, no HTTP-level response parsing. It's the bytes in, bytes out. Pair with `RawConnection` for end-to-end control.

### Test fixture mock — `blasthttp.mock`

`blasthttp.mock.BlasthttpMock` is a drop-in replacement for `BlastHTTP` that returns canned responses or invokes registered callbacks instead of hitting the network. Useful for unit tests that exercise code which calls into a `BlastHTTP` client.

```python
import asyncio
import re
import blasthttp
from blasthttp.mock import BlasthttpMock, MockResponse

async def main():
    mock = BlasthttpMock()

    # Static responses — declarative
    mock.add_response(url="https://api.example.com/users", json={"users": []})
    mock.add_response(url=re.compile(r"/v\d+/health"), text="ok")

    # Programmatic — callback receives a MockRequest, returns a MockResponse
    def echo(req):
        return MockResponse(status_code=201, json={"echoed": req.method})
    mock.add_callback(echo, url="https://api.example.com/echo")

    # Use it like a real client
    r = await mock.request("https://api.example.com/users")
    print(r.json())                    # {"users": []}
    print(isinstance(r, blasthttp.Response))   # True

    # Batch streaming works the same as the real client
    configs = [blasthttp.BatchConfig(f"https://api.example.com/users/{i}") for i in range(5)]
    mock.add_response(url=re.compile(r"/users/\d+"), json={"id": 0})
    async for r in mock.request_batch_stream(configs):
        ...

asyncio.run(main())
```

Key behaviors:

- **Matchers**: `url` accepts `str` (exact) or `re.Pattern` (`.search()` semantics) or `None` (any). `method` is case-insensitive. `match_headers={...}` and `match_json={...}` add subset predicates against the request headers / decoded JSON body.
- **FIFO + recycle**: handlers are matched in registration order. Once consumed, a handler is moved to a recycle queue so subsequent requests can re-match it — no need to re-register for repeated calls.
- **Callbacks**: sync and async (`async def`) both supported. Callbacks may raise `TimeoutException` or any other exception to simulate failures. Returning `MockResponse` is most ergonomic; returning a `blasthttp.Response` directly also works.
- **Pass-through**: pass a `real_client` and a `should_mock_fn(host) -> bool` predicate to forward selected requests to a real `BlastHTTP` instance. Common use case: mock everything except `127.0.0.1` so a fixture HTTP server stays exercised.

```python
real = blasthttp.BlastHTTP()
mock = BlasthttpMock(real_client=real, should_mock_fn=lambda h: h != "127.0.0.1")
mock.add_response(url="https://example.com/", text="mocked")
# https://example.com/ → mocked, http://127.0.0.1/* → real_client
```

Pytest integration is intentionally left to the consumer — wrap the mock in a fixture in your `conftest.py`:

```python
import pytest
from blasthttp.mock import BlasthttpMock

@pytest.fixture
def http_mock():
    return BlasthttpMock()
```

## Building

### Prerequisites

- Rust (2024 edition) — install via [rustup](https://rustup.rs/)
- Python 3.10+ (for Python bindings)
- Standard C build tools (`build-essential` / `gcc`, `make`, `perl`)
- `curl` or `wget` (for OpenSSL download)

### 1. Build custom OpenSSL

blasthttp ships a script that downloads OpenSSL 3.3.2, compiles it with weak cipher support (`RC4`, `DES`, `3DES`, export ciphers, `SSLv3`), and installs it to `vendor/openssl/install/`. This only needs to be run once — the result is cached and reused.

```bash
./scripts/build-openssl.sh
```

This produces a static build (`libssl.a`, `libcrypto.a`) with the legacy provider baked in. The binary has no runtime dependency on system OpenSSL. Delete `vendor/openssl/install/` to force a rebuild.

### 2. Build the Rust CLI

```bash
cargo build --release
```

The binary is at `target/release/blasthttp`. If you skip step 1, the build will fail with a clear error telling you to run the OpenSSL script.

### 3. Build the Python module

Requires [maturin](https://github.com/PyO3/maturin):

```bash
pip install maturin
maturin develop --release
```

This compiles the Rust code with Python bindings enabled and installs the `blasthttp` package into your current Python environment. You can then `import blasthttp` from Python.

### How it fits together

- `.cargo/config.toml` sets `OPENSSL_DIR` (relative path to `vendor/openssl/install/`) and `OPENSSL_STATIC=1` so the `openssl-sys` crate links against the custom build statically
- `build.rs` runs before compilation and verifies the custom OpenSSL headers exist, failing fast with an actionable error if they don't
- The `[features] python` gate means `cargo build` produces a pure Rust binary, while `maturin build` activates PyO3 and produces a Python-loadable `.so`
