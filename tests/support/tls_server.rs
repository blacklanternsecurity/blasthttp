// Shared test helper: a minimal HTTPS server using OpenSSL directly.
// Accepts one connection, does TLS handshake, sends a hardcoded HTTP response,
// then shuts down. Configurable cipher list and TLS version range.

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslMethod, SslOptions, SslVersion};
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
// `SSL_CTX_set_client_hello_cb` fires after the hello is parsed and before a
// cipher is chosen, which is the only point where the full offer is still
// visible. The safe `openssl` wrapper covers ciphers and versions but has no
// accessor for the extension list, so those go through openssl-sys.

/// Split a big-endian `u16` array, as TLS encodes cipher and extension lists.
fn be_u16s(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// Read one extension's body, or `None` when the client didn't send it.
fn extension_body(ssl: &mut openssl::ssl::SslRef, ext_type: u16) -> Option<Vec<u8>> {
    use foreign_types_shared::ForeignTypeRef;
    let mut out: *const std::ffi::c_uchar = std::ptr::null();
    let mut outlen: usize = 0;
    let found = unsafe {
        openssl_sys::SSL_client_hello_get0_ext(
            ssl.as_ptr(),
            ext_type as std::ffi::c_uint,
            &mut out,
            &mut outlen,
        )
    };
    if found != 1 || out.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(out, outlen) }.to_vec())
}

/// A TLS vector whose length prefix is two bytes, which is how
/// `supported_groups` and `signature_algorithms` wrap their contents.
fn u16_vector_body(body: &[u8]) -> Vec<u16> {
    if body.len() < 2 {
        return Vec::new();
    }
    let len = u16::from_be_bytes([body[0], body[1]]) as usize;
    be_u16s(&body[2..(2 + len).min(body.len())])
}

fn parse_alpn(body: &[u8]) -> Vec<String> {
    // Two-byte list length, then repeated one-byte-length-prefixed names.
    if body.len() < 2 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 2;
    while i < body.len() {
        let n = body[i] as usize;
        i += 1;
        if i + n > body.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&body[i..i + n]).into_owned());
        i += n;
    }
    out
}

fn capture_hello(ssl: &mut openssl::ssl::SslRef) -> CapturedHello {
    use foreign_types_shared::ForeignTypeRef;

    let mut captured = CapturedHello {
        legacy_version: unsafe {
            openssl_sys::SSL_client_hello_get0_legacy_version(ssl.as_ptr()) as u16
        },
        ciphers: ssl.client_hello_ciphers().map(be_u16s).unwrap_or_default(),
        ..Default::default()
    };

    // Extension types, in the order the client sent them. The array is
    // allocated by OpenSSL and is ours to free.
    let mut types: *mut std::ffi::c_int = std::ptr::null_mut();
    let mut count: usize = 0;
    let ok = unsafe {
        openssl_sys::SSL_client_hello_get1_extensions_present(ssl.as_ptr(), &mut types, &mut count)
    };
    if ok == 1 && !types.is_null() {
        captured.extensions = unsafe { std::slice::from_raw_parts(types, count) }
            .iter()
            .map(|t| *t as u16)
            .collect();
        unsafe { openssl_sys::OPENSSL_free(types as *mut std::ffi::c_void) };
    }

    captured.has_sni = captured.extensions.contains(&0x0000);
    if let Some(b) = extension_body(ssl, 0x000a) {
        captured.groups = u16_vector_body(&b);
    }
    if let Some(b) = extension_body(ssl, 0x000d) {
        captured.sig_algs = u16_vector_body(&b);
    }
    if let Some(b) = extension_body(ssl, 0x0010) {
        captured.alpn = parse_alpn(&b);
    }
    if let Some(b) = extension_body(ssl, 0x002b) {
        // supported_versions uses a ONE-byte length prefix, unlike the others.
        if !b.is_empty() {
            let len = b[0] as usize;
            captured.supported_versions = be_u16s(&b[1..(1 + len).min(b.len())]);
        }
    }

    captured
}

fn build_acceptor(config: &TlsServerConfig, hello: HelloSlot) -> SslAcceptor {
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

    // Record the client's offer before a cipher is picked.
    builder.set_client_hello_callback(move |ssl, _alert| {
        let captured = capture_hello(ssl);
        if let Ok(mut slot) = hello.lock() {
            *slot = Some(captured);
        }
        Ok(openssl::ssl::ClientHelloResponse::SUCCESS)
    });

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

    builder.build()
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
        let acceptor = build_acceptor(&config, hello.clone());

        // Bind to random port on localhost
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            let response = format!(
                "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                config.response_status,
                config.response_body.len(),
                config.response_body,
            );

            tokio::select! {
                result = listener.accept() => {
                    if let Ok((tcp_stream, _)) = result {
                        // Async TLS handshake via tokio-openssl
                        let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                        let mut tls_stream = match tokio_openssl::SslStream::new(ssl, tcp_stream) {
                            Ok(s) => s,
                            Err(_) => return,
                        };

                        // Perform the TLS accept handshake
                        if std::pin::Pin::new(&mut tls_stream).accept().await.is_err() {
                            // Handshake failed — expected for cipher/version mismatch tests
                            return;
                        }

                        // Read the HTTP request (we don't care about contents)
                        let mut buf = [0u8; 4096];
                        let _ = tls_stream.read(&mut buf).await;

                        // Send response
                        let _ = tls_stream.write_all(response.as_bytes()).await;
                        let _ = tls_stream.shutdown().await;
                    }
                }
                _ = shutdown_rx => {
                    // Shutdown requested
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
