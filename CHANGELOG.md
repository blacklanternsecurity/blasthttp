# Changelog

## 1.0.0

Breaking: a request that names no profile now sends `modern`, which is 11
suites and TLS 1.2 or 1.3. A server too old for that is still reached, by
the ladder falling back to `compatibility` on the second handshake.

- **Connection profiles.** Three of them. `compatibility` offers every suite
  the build provides and every protocol version back to SSLv3. `modern` offers
  11 current suites and claims nothing. `chrome131` imitates Chrome's TLS,
  HTTP/2 settings and headers together. Select one with `profile=`; an unknown
  name is now an error rather than silently falling back
- **Automatic shifting between them.** A handshake failure that suggests the
  peer could not negotiate widens the offer; a refusal from a recognised
  protection product changes what the client claims to be. Per redirect hop,
  since a redirect can land on a differently protected host, and without
  spending the caller's retry budget, which is a different question. A profile
  that gets through is remembered per host so a scan does not re-walk the
  ladder on every request. Naming a `profile`, `cipher_string`,
  `min_tls_version` or `max_tls_version` pins the configuration and the ladder
  does not move
- The ladder only moves on positive evidence that a product intervened, not on
  any refusal. Most 403s are ordinary authorization failures, and retrying each
  one with different TLS settings would double the request count of any scan
  that touches one
- A host that refuses every rung is remembered too, for ten minutes: during
  that time a refusal from it is taken as the answer after one request, rather
  than walking the ladder again. Only success used to be remembered, so a host
  that refused everything cost two requests for every one a scan sent it, on
  exactly the hosts most likely to rate-limit or ban. Getting through clears
  it, and it expires because a refusal is a judgement that changes
- **`Response.protection`** reports what a bot-management product did:
  `(outcome, vendor)` where outcome is ok, present, challenge, blocked or error
- **`Response.conclusion`** reduces that to one verdict: reached, blocked,
  needs_browser, needs_legacy_tls or unreachable. `needs_browser` means a
  JavaScript challenge, which no HTTP client passes, so the URL should go to a
  real browser rather than be retried
- **`Response.attempts`** lists what the ladder tried, in order
- Imperva's `_Incapsula_Resource` loader script no longer counts as a
  challenge. Imperva appends it to pages it let through, so ordinary pages and
  the origin's own error pages were judged `needs_browser`. Imperva's incident
  page still counts
- **The anti-bot rules are data.** What `protection` recognises now lives in
  `antibot_rules.json` instead of code, and `blasthttp.set_antibot_rules(path)`
  (`antibot::set_rules` in Rust) replaces them at runtime, so a rule can change
  without a rebuild. `Vendor` is a name rather than a fixed list, so a rules
  file can add a product
- **TLS failures now say why.** The reason used to be destroyed in transit:
  hyper-util's error displays as the literal "client error (Connect)" for every
  connect-time failure, so a cipher mismatch, a rejected certificate, a DNS
  failure and a refused connection were indistinguishable. Failures now raise
  `TransportError` carrying `kind`, `tls_failure`, `retryable`, `conclusion`
  and `attempts`. `TransportError` subclasses `RuntimeError`, so existing
  handlers keep working
- Fixes a consequence of that: TLS failures were being retried, because they
  were misclassified as connection errors, contradicting the rule that says
  they should not be
- Connect failures before TLS say why too. A refused connection, a DNS failure
  or a proxy that refuses the tunnel now includes the cause, e.g. "tcp connect
  error: Connection refused (os error 111)", not only "client error
  (Connect)", and a connect timeout is reported as a timeout instead of a
  retryable connection error
- Batch failures carry the same detail. `BatchResult.transport_error` is the
  `TransportError` that `request()` would have raised, with `kind`,
  `retryable`, `conclusion` and the rest. `error` is still the message string
- `blasthttp.mock` raises `TransportError` where the real client would: for a
  URL with no mock response (`kind="connection"`) and for too many redirects
  (`kind="too_many_redirects"`). A mocked batch request for an unmocked URL
  gets a `transport_error` too
- Asking for a pre-TLS1.2 version without naming a profile now selects
  `compatibility`, rather than failing with "no ciphers available" because the
  default offers nothing that exists in SSLv3
- `BLASTHTTP_BISECT=tls,headers,http2` disables profile layers independently,
  for finding out which one a detector is reacting to
- Batches no longer have every request in an opening burst work out the same
  host's profile separately. A request whose host is already being discovered
  stands aside and lets a request for a *different* host take its slot, then
  goes once there is an answer. Six requests to a host needing a shift went
  from twelve handshakes to seven, with nothing idling: standing aside only
  happens when there is undispatched work elsewhere, so when a batch is all
  one host every request goes immediately and discovers it again, which is the
  cheaper mistake. A slow request still never holds up faster ones behind it.
  Measured over a grid of batch shapes, the duplicate handshakes go to zero in
  every one: a scan of 2000 URLs across 20 hosts drops 62 handshakes, 500 URLs
  across 10 hosts drops 139, and wall time is unchanged. A batch no deeper than
  its own concurrency limit pays one extra round trip for it, since there the
  discovery cannot be overlapped with anything
- `raw_connect`, and requests using `resolve_ip` or `request_target`, widen
  their cipher offer and retry on a handshake the peer could not negotiate,
  the same as an ordinary request. They stop at that rung: the other one
  reacts to a refusal by changing what the client claims to be, and these are the callers who asked for exact
  control over one request
- `download()` takes `profile`, `cipher_string`, `min_tls_version`,
  `max_tls_version` and `redirect_cookies`. It hardcoded no profile with no
  way to pass one, so a file behind a host that only answers a browser was
  unreachable through `download` while the same URL through `request` was fine
- `blasthttp.mock` forwards every kwarg to the real client on a passthrough
  request. It named six and dropped the rest, so a URL excluded from mocking
  was dialled with different TLS, a different profile and no timeout from what
  the caller asked for
- A request that names a profile no longer writes it into the per-host memory.
  Reads already skipped the memory when the caller pinned something; writes
  did not, so one deliberate `profile="chrome"` request turned every later
  request to that host into a browser claim, and made the outcome depend on
  the order two unrelated requests ran in
- Legacy ciphers are reachable, which is what the custom OpenSSL build has always been for. `compatibility` offers every suite the build provides, so a server speaking only RC4, RC4-MD5, 3DES, SEED, Camellia or anonymous DH is reachable without passing `cipher_string` yourself
- Null-encryption suites are the deliberate exception. They stay reachable through an explicit `cipher_string` but are never offered by any profile, since negotiating one by accident returns a connection that looks like TLS and encrypts nothing
- The profile's cipher list applies on both TLS paths, the pooled client and the `resolve_ip` / `request_target` / `raw_connect` path, which build their SSL contexts separately
- SSLv3 works. `min_tls_version` / `max_tls_version` / `--min-tls` / `--max-tls` accept `3.0` (also `ssl3`, `sslv3`), and an SSLv3-only server is reachable without asking for it
- The OpenSSL build cache is keyed on the feature flags and version as well as the target, so changing what the build asks for triggers a rebuild. The first run after upgrading rebuilds once
- Export ciphers are not supported. OpenSSL removed them outright in 1.1.0, so no build flag brings them back
- A TLS failure is reported only for the request that hit it. A later error to the same host, such as a refused connection, is classified on its own and retried as usual
- A `cipher_string` with no `profile` named selects `compatibility`, the same as asking for a pre-1.2 TLS version, so no TLS 1.2 floor applies and `cipher_string="RC4-MD5"` reaches a TLS 1.0 server. Naming a profile as well keeps that profile's floor
- `Content-Encoding: zstd` is decoded, including bodies of several frames. `chrome131` advertises it, as Chrome does, and Cloudflare answers with it. A frame asking for a window over 8 MiB (RFC 9659's limit) is refused and the body returned undecoded, so a response can't make the client allocate an arbitrary window
- With `verify_certs` on, anonymous (aNULL) suites are never offered, including from an explicit `cipher_string`. They send no certificate, so verification would report success while checking nothing. With verification off, nothing is excluded

## 0.10.1

- Python 3.15 support: PyO3 0.30, and 3.15 wheels are published
- CI tests 3.11 through 3.15; 3.10 wheels are still published but no longer tested
- Dependency updates (brotli 9, hyper 1.12, tokio 1.53.3, and others)

## 0.10.0

- Cookies set on a redirect hop are applied to the hops that follow it, the way a browser does. What a chain collects lives for that one request, so nothing carries between requests
- What a chain will hold is capped (4096 bytes per cookie, 50 cookies, 8KB total), so a response that sets hundreds of large cookies can't grow every later hop's `Cookie` header without bound
- A `Domain` attribute is checked against the Public Suffix List, so `Domain=com`, `Domain=co.uk` or `Domain=github.io` can't be used to carry a cookie onto an unrelated host, and a cookie may only widen within one registrable domain
- A cookie set in the request's own `Cookie` header always wins: every hop sends it, and a `Set-Cookie` naming it is ignored rather than replacing it, deleting it, or being sent alongside it
- `redirect_cookies=False` (or `--no-redirect-cookies`) reverts to the previous behavior
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
