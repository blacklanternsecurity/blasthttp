# Changelog

## 0.10.0

- Fix responses being discarded when `Content-Encoding` is declared on an empty body (bodyless redirects, `HEAD`, `304`)
- `max_body_size` now bounds the decompressed body, not just the bytes read off the wire
- A compressed body cut short by `max_body_size` keeps whatever inflated instead of failing the whole request
- Decode stacked encodings (`Content-Encoding: gzip, br`) and the `x-gzip` alias, which previously returned the body still compressed
- A body that doesn't match its declared `Content-Encoding` is returned undecoded instead of failing the request, so the response is never dropped over a body we can't read
- `alpn_protocols` on `request()`, to pick the ALPN offer on the pooled path (default unchanged: h2 then http/1.1)

## 0.9.0

- `no_proxy` support — bypass the proxy for specific hosts, domains, IPs, or CIDRs
- `no_proxy` re-evaluated on every redirect hop
- `--rate-limit` CLI flag for batch mode

## 0.8.0

- `no_proxy` initial implementation (per-request)

## 0.7.0

- Fix duplicate Host header on pooled HTTP/2 connections

## 0.6.0

- Multipart file uploads (`files=` parameter, httpx-style)
- Reject `body` and `files` together with `ValueError`

## 0.5.0

- `blasthttp.mock` submodule for test fixtures (drop-in `BlastHTTP` replacement)
- httpx-style Response API — lazy `body`, `cookies`, `raw_headers`, `hash`
- `peer_ip` on every response and redirect hop

## 0.4.0

- `request_batch_stream()` — async iterator that yields results as they complete

## 0.3.0

- `blasthttp.h2` — permissive HPACK encoder/decoder and HTTP/2 frame builders
- HPACK decoder with dynamic table tracking
- RawConnection inherits client rate limiter

## 0.2.0

- Async Python API via `pyo3-async-runtimes`
- `RawConnection` for byte-level TCP/TLS I/O
- ALPN protocol negotiation on `raw_connect()`
- Proxy support for raw connections (HTTP CONNECT + SOCKS5)

## 0.1.1

- Initial release
- Batch HTTP client with connection pooling
- Custom OpenSSL 3.3.2 with legacy cipher support
- HTTP/2 via ALPN negotiation
- TLS cert extraction (CN, SANs, issuer)
- Response hashing (MD5, SHA256, MurmurHash3)
- Python bindings with retries, rate limiting, and download
- `resolve_ip` (DNS pinning) and `request_target` (request-line override)
- CLI with batch mode and JSON output
