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
- **SSL cert info on every request** — extracts CN, SANs, and issuer during the TLS handshake that's already happening, eliminating the need for a separate sslcert connection
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

# Force specific TLS versions/ciphers
blasthttp https://legacy-server.com --min-tls 1.0 --ciphers "RC4-SHA"

# Verbose output (pretty JSON + debug info, -vv includes body)
blasthttp https://example.com -v
```

Output is JSON (one object per response), including status, headers, redirect chain, TLS cert info, and content hashes:

```json
{
  "url": "https://example.com",
  "status": 200,
  "headers": [["content-type", "text/html"], ...],
  "elapsed_ms": 120,
  "redirect_chain": [],
  "cert_info": {
    "common_name": "example.com",
    "sans": ["example.com", "www.example.com"],
    "issuer": "DigiCert Global G2",
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
| `-L, --follow-redirects` | Follow redirects | off |
| `--max-redirects` | Max redirect hops | `10` |
| `-t, --timeout` | Request timeout (seconds) | `10` |
| `--max-body-size` | Max response body (bytes) | 10 MB |
| `--verify` | Enable TLS cert validation | off |
| `-x, --proxy` | HTTP/SOCKS proxy URL | |
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

    # Single request
    response = await client.request("https://example.com")
    print(response.status, len(response.body))

    # Batch requests — full result list at the end
    configs = [
        blasthttp.BatchConfig("https://a.com"),
        blasthttp.BatchConfig("https://b.com", method="POST", body="data"),
    ]
    results = await client.request_batch(configs, concurrency=50)
    for r in results:
        if r.success:
            print(r.url, r.response.status)

    # Streaming batch — process results as they complete
    async for batch in client.request_batch_stream(configs, concurrency=50):
        for r in batch:
            if r.success:
                print(r.url, r.response.status)

    # Download to file
    await client.download("https://example.com/file.zip", "/tmp/file.zip")

asyncio.run(main())
```

### Batch vs. streaming batch

Two shapes for issuing the same workload — pick whichever matches how you want to consume the results:

| | Returns | Consume with | When to use |
|---|---|---|---|
| `request_batch(configs, ...)` | `list[BatchResult]` after every request finishes | `results = await ...; for r in results:` | You want the full set in one shot. |
| `request_batch_stream(configs, ...)` | async iterator of `list[BatchResult]` chunks, in completion order | `async for batch in ...: for r in batch:` | A slow request shouldn't block faster peers behind it; you want to overlap consumer work with in-flight HTTP I/O; partial results are useful before the slowest finishes. |

`request_batch_stream` yields up to 1000 results per chunk, or whatever has accumulated after ~200ms — the timeout flushes partial chunks so the consumer is never starved when results trickle in slowly. Both functions accept the same `(configs, concurrency=50, rate_limit=None)` arguments and respect `set_rate_limit()` identically.

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

`raw_connect()` takes all the same TLS knobs as `request()` — `verify_certs`, `cipher_string`, `min_tls_version`, `max_tls_version`, `resolve_ip`, `proxy`. `alpn_protocols` is a list of byte-strings (commonly `["h2", "http/1.1"]`) used in the TLS ALPN extension. After the handshake, `conn.negotiated_alpn` reports which one the server picked (or `None` if no ALPN was negotiated, including all plain-HTTP connections).

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

## Status

Work in progress. Targeting BBOT integration.
