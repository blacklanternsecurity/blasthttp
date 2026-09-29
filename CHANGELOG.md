# Changelog

## 1.0.0

Breaking: a request that names no profile no longer offers 105 cipher suites
and every protocol version back to SSLv3. It sends `modern` instead, which is
11 suites and TLS 1.2 or 1.3. A server too old for that is still reached, by
the ladder falling back to `compatibility` on the second handshake.

- **Connection profiles.** Three of them. `compatibility` is a faithful
  transcription of what 0.10 sent by default, kept byte-identical and verified
  by the existing tests. `modern` is new. `chrome131` imitates Chrome's TLS,
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
- **`Response.protection`** reports what a bot-management product did:
  `(outcome, vendor)` where outcome is ok, present, challenge, blocked or error
- **`Response.conclusion`** reduces that to one verdict: reached, blocked,
  needs_browser, needs_legacy_tls or unreachable. `needs_browser` means a
  JavaScript challenge, which no HTTP client passes, so the URL should go to a
  real browser rather than be retried
- **`Response.attempts`** lists what the ladder tried, in order
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
- Asking for a pre-TLS1.2 version without naming a profile now selects
  `compatibility`, rather than failing with "no ciphers available" because the
  default offers nothing that exists in SSLv3
- `BLASTHTTP_BISECT=tls,headers,http2` disables profile layers independently,
  for finding out which one a detector is reacting to
- `raw_connect`, and requests using `resolve_ip` or `request_target`, widen
  their cipher offer and retry on a handshake the peer could not negotiate,
  the same as an ordinary request. These bypass the pooled client, so they
  bypassed the ladder too, and when the default narrowed from 105 suites to 11
  they quietly lost the legacy reach the custom OpenSSL build exists to give
  them. They stop at that rung: the other one reacts to a refusal by changing
  what the client claims to be, and these are the callers who asked for exact
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

## 0.10.1

- Legacy ciphers are offered by default, which is what the custom OpenSSL build has always been for. A server speaking only RC4, RC4-MD5, 3DES, SEED, Camellia or anonymous DH is now reachable without passing `cipher_string` yourself. Previously `SslConnector::builder` installed its own list (`DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:...`) and nothing replaced it, so those suites never reached the wire and such a server was unreachable at any setting. `set_security_level(0)` did not help: the security level governs how weak a negotiated cipher may be, not which ones are offered
- Null-encryption suites are the deliberate exception. They stay reachable through an explicit `cipher_string` but are never offered by default, since negotiating one by accident returns a connection that looks like TLS and encrypts nothing
- The default applies on both TLS paths, the pooled client and the `resolve_ip` / `request_target` / `raw_connect` path, which build their SSL contexts separately
- This widens the ClientHello from 31 cipher suites to 105, which changes the client's TLS fingerprint. Anything matching on JA3/JA4 will see a different value than it did on 0.10.0
- SSLv3 works, for the first time. It had never been reachable in any build: `scripts/build-openssl.sh` passed `enable-ssl3`, but OpenSSL's Configure has a disable cascade reading "if `ssl3-method` is off, turn `ssl3` off too", and `ssl3-method` is off by default. The flag was silently undone, so every shipped build had `OPENSSL_NO_SSL3` defined and no `SSLv3_method` symbols. The script now passes `enable-ssl3-method` as well
- `SslConnector::builder` also sets `NO_SSLV3`, which nothing cleared, and `parse_tls_version` only understood 1.0 through 1.3, so SSLv3 had no spelling even if the build had provided it. Both are fixed: the option is cleared on both TLS paths, and `min_tls_version` / `max_tls_version` / `--min-tls` / `--max-tls` now accept `3.0` (also `ssl3`, `sslv3`). An SSLv3-only server is reachable without asking for it
- The OpenSSL build cache is keyed on the feature flags and version as well as the target, so changing what the build asks for now triggers a rebuild instead of silently reusing a build made a different way. The first run after upgrading rebuilds once
- README no longer claims export ciphers work. OpenSSL removed them outright in 1.1.0, so no build flag brings them back

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
