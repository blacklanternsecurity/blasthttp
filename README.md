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
