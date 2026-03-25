# blasthttp

Offensive-first HTTP library written in Rust with Python bindings. Built for [BBOT](https://github.com/blacklanternsecurity/bbot).

## Key Advantages

- **Batch connection reuse** — connections are pooled and reused within a batch, dramatically reducing overhead when scanning many URLs on the same hosts
- **Rust performance** — async I/O, zero-copy where possible, and native concurrency give significant speed improvements over pure Python HTTP clients
- **SSL cert info on every request** — extracts CN, SANs, and issuer during the TLS handshake that's already happening, eliminating the need for a separate sslcert connection
- **All TLS ciphers available by default** — custom-compiled OpenSSL 3.3.2 with legacy provider baked in (RC4, 3DES, export ciphers, SSLv3) so you can connect to anything
- **No cert validation by default** — offensive-first: connects to self-signed, expired, and misconfigured TLS without extra config
- **HTTP/2 support** — automatic via ALPN negotiation, falls back to HTTP/1.1
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

```python
import blasthttp

client = blasthttp.BlastHTTP()

# Single request
response = client.request("https://example.com")
print(response.status, len(response.body))

# Batch requests
configs = [
    {"url": "https://a.com"},
    {"url": "https://b.com", "method": "POST", "body": "data"},
]
results = client.request_batch(configs, concurrency=50)
for r in results:
    if r.success:
        print(r.url, r.response.status)

# Download to file
client.download("https://example.com/file.zip", "/tmp/file.zip")
```

### Global Rate Limiting

Set a client-level rate limit (requests per second) that applies to **all** request methods — `request()`, `request_batch()`, and `download()`:

```python
client = blasthttp.BlastHTTP()
client.set_rate_limit(50)  # 50 requests/sec across all callers

# All of these respect the 50 rps limit:
client.request("https://example.com")
client.request_batch(configs, concurrency=100)
client.download("https://example.com/file", "/tmp/file")

# Disable rate limiting
client.set_rate_limit(0)
# or
client.set_rate_limit(None)
```

When multiple callers share the same `BlastHTTP` instance, the rate limiter is global — two concurrent `request_batch()` calls will collectively stay under the limit.

The client-level rate limit takes precedence over the per-call `rate_limit` parameter on `request_batch()`.

## Building

### Prerequisites

- Rust (2024 edition) — install via [rustup](https://rustup.rs/)
- Python 3.9+ (for Python bindings)
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
