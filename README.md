# blasthttp

Offensive-first HTTP library written in Rust with Python bindings. Built for [BBOT](https://github.com/blacklanternsecurity/bbot).

## Key Advantages

- **Batch connection reuse** — connections are pooled and reused within a batch, dramatically reducing overhead when scanning many URLs on the same hosts
- **Rust performance** — async I/O, zero-copy where possible, and native concurrency give significant speed improvements over pure Python HTTP clients
- **SSL cert info on every request** — extracts CN, SANs, and issuer during the TLS handshake that's already happening, eliminating the need for a separate sslcert connection
- **All TLS ciphers available by default** — custom-compiled OpenSSL 3.3.2 with legacy provider baked in (RC4, 3DES, export ciphers, SSLv3) so you can connect to anything
- **No cert validation by default** — offensive-first: connects to self-signed, expired, and misconfigured TLS without extra config
- **HTTP/2 support** — modern servers that require h2 just work (TODO)

## Status

Work in progress. Phase 2 complete (batch mode, concurrency, proxy, custom OpenSSL). Targeting BBOT integration.
