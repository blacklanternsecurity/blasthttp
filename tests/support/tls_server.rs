// Shared test helper: a minimal HTTPS server using OpenSSL directly.
// Accepts one connection, does TLS handshake, sends a hardcoded HTTP response,
// then shuts down. Configurable cipher list and TLS version range.

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{AlpnError, SslAcceptor, SslAcceptorBuilder, SslMethod, SslOptions, SslVersion};
use openssl::x509::X509;
use openssl::x509::extension::SubjectAlternativeName;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The parts of a ClientHello that make up a TLS fingerprint.
///
/// Read back server-side from the handshake the client under test actually
/// sent, so it reflects what went on the wire rather than what the config
/// asked for. Those differ more often than you would like: `cipher_string`
/// only governs TLS 1.2 and below, for instance, so the 1.3 suite list comes
/// from somewhere else entirely.
#[derive(Debug, Clone, Default)]
pub struct CapturedHello {
    /// The legacy `client_version` field, which is pinned at TLS 1.2 on any
    /// modern hello. The real version lives in `supported_versions`.
    pub legacy_version: u16,
    /// Cipher suites in the order offered, GREASE included.
    pub ciphers: Vec<u16>,
    /// Extension types in the order sent, GREASE included.
    pub extensions: Vec<u16>,
    /// `supported_groups` (0x000a) contents, GREASE included.
    pub groups: Vec<u16>,
    /// `signature_algorithms` (0x000d) contents, in the order sent.
    pub sig_algs: Vec<u16>,
    /// ALPN protocol names offered, in order.
    pub alpn: Vec<String>,
    /// `supported_versions` (0x002b) contents, GREASE included.
    pub supported_versions: Vec<u16>,
    /// Whether a `server_name` (0x0000) extension was present.
    pub has_sni: bool,
}

/// Where a capturing server leaves what it saw. `None` until a client
/// completes enough of a handshake to send its hello.
pub type HelloSlot = std::sync::Arc<std::sync::Mutex<Option<CapturedHello>>>;

pub struct TlsTestServer {
    pub addr: SocketAddr,
    /// What the client sent, once it has connected.
    pub hello: HelloSlot,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
}

pub struct TlsServerConfig {
    pub cipher_list: Option<String>,
    pub min_tls_version: Option<SslVersion>,
    pub max_tls_version: Option<SslVersion>,
    pub response_body: String,
    pub response_status: u16,
    /// DNS SANs for the self-signed cert. Default: ["localhost"].
    pub san_dns: Vec<String>,
    /// IP SANs for the self-signed cert. Default: ["127.0.0.1"].
    pub san_ip: Vec<String>,
}

impl Default for TlsServerConfig {
    fn default() -> Self {
        TlsServerConfig {
            cipher_list: None,
            min_tls_version: None,
            max_tls_version: None,
            response_body: "OK".to_string(),
            response_status: 200,
            san_dns: vec!["localhost".to_string()],
            san_ip: vec!["127.0.0.1".to_string()],
        }
    }
}

// Generate a self-signed cert + key pair in memory (no files needed)
fn generate_self_signed(config: &TlsServerConfig) -> (PKey<openssl::pkey::Private>, X509) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();

    let serial = BigNum::from_u32(1).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    builder.set_issuer_name(&name).unwrap();
    builder.set_subject_name(&name).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(1).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.set_pubkey(&pkey).unwrap();

    let mut san = SubjectAlternativeName::new();
    for dns in &config.san_dns {
        san.dns(dns);
    }
    for ip in &config.san_ip {
        san.ip(ip);
    }
    let san = san.build(&builder.x509v3_context(None, None)).unwrap();
    builder.append_extension(san).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    (pkey, cert)
}

// ── ClientHello capture ───────────────────────────────────────────
//
// Parsed straight off the wire rather than through OpenSSL's
// `SSL_CTX_set_client_hello_cb`. That callback looks like the obvious tool and
// quietly under-reports: `SSL_client_hello_get1_extensions_present` only
// returns extensions the *server's* OpenSSL has a definition for, so anything
// it has not heard of is invisible. Since the extensions worth testing are
// precisely the ones OpenSSL does not implement, ALPS and ECH among them, that
// made the harness blind to the thing it exists to measure.
//
// Reading the bytes has two further benefits we need later: extension order
// survives, and so does GREASE. Both are invisible through the callback.

/// Split a big-endian `u16` array, as TLS encodes cipher and extension lists.
fn be_u16s(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// A cursor that refuses to run off the end, so a malformed or truncated hello
/// returns what was understood instead of panicking inside a test server.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    /// A TLS vector with a one- or two-byte length prefix.
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Parse a ClientHello out of one or more TLS records.
///
/// Returns `None` for anything that is not a well-formed handshake, which in a
/// test means the client failed before saying anything useful.
pub fn parse_client_hello(raw: &[u8]) -> Option<CapturedHello> {
    // Reassemble the handshake across records. A hello carrying a real
    // key_share and an ECH extension runs past 1400 bytes and is routinely
    // split, so reading only the first record would truncate it.
    let mut handshake = Vec::new();
    let mut r = Reader::new(raw);
    while r.pos < raw.len() {
        let content_type = r.u8()?;
        let _record_version = r.u16()?;
        let fragment = r.vec16()?;
        if content_type != 0x16 {
            return None; // not a handshake record
        }
        handshake.extend_from_slice(fragment);
    }

    let mut h = Reader::new(&handshake);
    if h.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let len = {
        let b = h.take(3)?;
        ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
    };
    let body = h.take(len)?;

    let mut b = Reader::new(body);
    let legacy_version = b.u16()?;
    b.take(32)?; // random
    b.vec8()?; // session id
    let ciphers = be_u16s(b.vec16()?);
    b.vec8()?; // compression methods

    let mut captured = CapturedHello {
        legacy_version,
        ciphers,
        ..Default::default()
    };

    // Extensions are optional in the grammar, though nothing modern omits them.
    let Some(ext_block) = b.vec16() else {
        return Some(captured);
    };

    let mut e = Reader::new(ext_block);
    while e.pos < ext_block.len() {
        let Some(ext_type) = e.u16() else { break };
        let Some(data) = e.vec16() else { break };
        captured.extensions.push(ext_type);

        let mut d = Reader::new(data);
        match ext_type {
            0x0000 => captured.has_sni = true,
            0x000a => {
                if let Some(v) = d.vec16() {
                    captured.groups = be_u16s(v);
                }
            }
            0x000d => {
                if let Some(v) = d.vec16() {
                    captured.sig_algs = be_u16s(v);
                }
            }
            0x0010 => {
                if let Some(list) = d.vec16() {
                    let mut l = Reader::new(list);
                    while l.pos < list.len() {
                        match l.vec8() {
                            Some(name) => captured
                                .alpn
                                .push(String::from_utf8_lossy(name).into_owned()),
                            None => break,
                        }
                    }
                }
            }
            // supported_versions is the odd one out: a one-byte length prefix
            // where the others use two.
            0x002b => {
                if let Some(v) = d.vec8() {
                    captured.supported_versions = be_u16s(v);
                }
            }
            _ => {}
        }
    }

    Some(captured)
}

fn build_acceptor(config: &TlsServerConfig) -> SslAcceptor {
    acceptor_builder(config).build()
}

/// An acceptor that only speaks HTTP/2, for tests that serve with hyper's
/// h2 server instead of the hardcoded HTTP/1.1 response above.
pub fn build_h2_acceptor(config: &TlsServerConfig) -> SslAcceptor {
    let mut builder = acceptor_builder(config);
    builder.set_alpn_select_callback(|_, client| {
        openssl::ssl::select_next_proto(b"\x02h2", client).ok_or(AlpnError::NOACK)
    });
    builder.build()
}

fn acceptor_builder(config: &TlsServerConfig) -> SslAcceptorBuilder {
    // Load the legacy provider so the server can use weak ciphers too
    load_legacy_provider();

    // Build from scratch — no mozilla presets that restrict ciphers/versions.
    // mozilla_intermediate sets SSL options that can disable TLS 1.3.
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_security_level(0);
    // Clear ALL version restrictions and options
    builder.set_min_proto_version(None).unwrap();
    builder.set_max_proto_version(None).unwrap();
    // Remove any SSL options that might disable specific protocol versions,
    // SSLv3 included, so a test can pin the server to it.
    builder.clear_options(
        SslOptions::NO_TLSV1_3
            | SslOptions::NO_TLSV1_2
            | SslOptions::NO_TLSV1_1
            | SslOptions::NO_TLSV1
            | SslOptions::NO_SSLV3,
    );
    // Accept all ciphers by default
    builder
        .set_cipher_list("ALL:COMPLEMENTOFALL:eNULL")
        .unwrap();
    // TLS 1.3 ciphersuites are configured separately in OpenSSL 3.x
    builder
        .set_ciphersuites(
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
        )
        .unwrap();

    let (pkey, cert) = generate_self_signed(config);
    builder.set_private_key(&pkey).unwrap();
    builder.set_certificate(&cert).unwrap();

    if let Some(ref ciphers) = config.cipher_list {
        builder.set_cipher_list(ciphers).unwrap();
    }

    if let Some(min_ver) = config.min_tls_version {
        builder.set_min_proto_version(Some(min_ver)).unwrap();
    }

    if let Some(max_ver) = config.max_tls_version {
        builder.set_max_proto_version(Some(max_ver)).unwrap();
    }

    builder
}

// Load legacy provider for the test server (same as our client does)
static INIT_LEGACY: std::sync::Once = std::sync::Once::new();

fn load_legacy_provider() {
    INIT_LEGACY.call_once(|| {
        let _default = openssl::provider::Provider::try_load(None, "default", true)
            .expect("failed to load default provider");
        let _legacy = openssl::provider::Provider::try_load(None, "legacy", true)
            .expect("failed to load legacy provider");
        std::mem::forget(_default);
        std::mem::forget(_legacy);
    });
}

impl TlsTestServer {
    pub async fn start(config: TlsServerConfig) -> Self {
        let hello: HelloSlot = std::sync::Arc::new(std::sync::Mutex::new(None));
        let acceptor = build_acceptor(&config);

        // Bind to random port on localhost
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let hello_slot = hello.clone();
        let handle = tokio::spawn(async move {
            let response = format!(
                "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                config.response_status,
                config.response_body.len(),
                config.response_body,
            );

            // Serve connections until shutdown, rather than exactly one.
            //
            // One was enough while a failed handshake was the end of the
            // story. It is not any more: the profile ladder retries a refused
            // handshake with a wider offer, so every legacy-cipher test needs
            // at least two connections. With a single-shot server the second
            // attempt gets ECONNREFUSED and the test fails for a reason that
            // has nothing to do with what it is testing.
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((tcp_stream, _)) = result else { continue };

                        // Read the ClientHello off the wire and parse it
                        // before TLS touches it. Peeking rather than consuming
                        // keeps the stream intact, so no replay buffer is
                        // needed and the handshake proceeds as it would have.
                        //
                        // Overwritten per connection, so after a ladder walk
                        // the slot holds the LAST hello, which is the one that
                        // succeeded.
                        let mut peek = vec![0u8; 8192];
                        if let Ok(n) = tcp_stream.peek(&mut peek).await
                            && let Some(parsed) = parse_client_hello(&peek[..n])
                            && let Ok(mut slot) = hello_slot.lock()
                        {
                            *slot = Some(parsed);
                        }

                        let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                        let mut tls_stream = match tokio_openssl::SslStream::new(ssl, tcp_stream) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };

                        // A failed handshake is an ordinary event here, not
                        // the end: it is what the cipher and version mismatch
                        // tests are producing on purpose, and what the ladder
                        // then retries.
                        if std::pin::Pin::new(&mut tls_stream).accept().await.is_err() {
                            continue;
                        }

                        let mut buf = [0u8; 4096];
                        let _ = tls_stream.read(&mut buf).await;
                        let _ = tls_stream.write_all(response.as_bytes()).await;
                        let _ = tls_stream.shutdown().await;
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });

        TlsTestServer {
            addr,
            hello,
            shutdown_tx,
            handle,
        }
    }

    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.handle.await;
    }
}
