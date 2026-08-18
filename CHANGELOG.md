# Changelog

## Unreleased

- Cookies set on a redirect hop are applied to the hops that follow it, the way a browser does. What a chain collects lives for that one request, so nothing carries between requests
- What a chain will hold is capped (4096 bytes per cookie, 50 cookies, 8KB total), so a response that sets hundreds of large cookies can't grow every later hop's `Cookie` header without bound
- A `Domain` attribute is checked against the Public Suffix List, so `Domain=com`, `Domain=co.uk` or `Domain=github.io` can't be used to carry a cookie onto an unrelated host, and a cookie may only widen within one registrable domain
- A cookie set in the request's own `Cookie` header always wins: every hop sends it, and a `Set-Cookie` naming it is ignored rather than replacing it, deleting it, or being sent alongside it
- `redirect_cookies=False` (or `--no-redirect-cookies`) reverts to the previous behavior

## 0.10.0

- Fix responses being discarded when `Content-Encoding` is declared on an empty body (bodyless redirects, `HEAD`, `304`)
- `max_body_size` now bounds the decompressed body, not just the bytes read off the wire
- A compressed body cut short by `max_body_size` keeps whatever inflated instead of failing the whole request
- Decode stacked encodings (`Content-Encoding: gzip, br`) and the `x-gzip` alias, which previously returned the body still compressed
- A body that doesn't match its declared `Content-Encoding` is returned undecoded instead of failing the request, so the response is never dropped over a body we can't read
- `Response.decode_error` says why `content` is not decoded content, so compressed bytes can't be mistaken for a body by anything that hashes, matches, or diffs them
- Accept zlib-wrapped `deflate` (RFC 1950), which is what `Content-Encoding: deflate` is specified as and what IIS and several CDN fronts send; only bare deflate (RFC 1951) worked before
- Undo every `Content-Encoding` line, not just the first, so a doubled header from a proxy in front of a compressing backend no longer leaves the body compressed
- A stack of codings that only partly comes off keeps the deepest result rather than reverting to the bytes that arrived, since a header listing more codings than were applied (a proxy re-adding `Content-Encoding: gzip` without compressing again) is the common case and that result is the body
- `max_body_size` now stops the read instead of buffering the whole body and slicing it, so a target can't answer with an unbounded body regardless of the cap
- `alpn_protocols` on `request()`, to pick the ALPN offer (defaults unchanged: h2 then http/1.1 pooled, http/1.1 alone on the `resolve_ip` / `request_target` path)
- Requests with `resolve_ip` set now speak HTTP/2 when ALPN negotiates it, instead of negotiating h2 and then sending HTTP/1.1 over it. `request_target` with an h2 offer is rejected outright, since h2 has no request-line to override

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
