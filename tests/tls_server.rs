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

pub struct TlsTestServer {
    pub addr: SocketAddr,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
}

pub struct TlsServerConfig {
    pub cipher_list: Option<String>,
    pub min_tls_version: Option<SslVersion>,
    pub max_tls_version: Option<SslVersion>,
    pub response_body: String,
    pub response_status: u16,
}

impl Default for TlsServerConfig {
    fn default() -> Self {
        TlsServerConfig {
            cipher_list: None,
            min_tls_version: None,
            max_tls_version: None,
            response_body: "OK".to_string(),
            response_status: 200,
        }
    }
}

// Generate a self-signed cert + key pair in memory (no files needed)
fn generate_self_signed() -> (PKey<openssl::pkey::Private>, X509) {
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

    // Add SAN for localhost + 127.0.0.1
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .ip("127.0.0.1")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(san).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    (pkey, cert)
}

fn build_acceptor(config: &TlsServerConfig) -> SslAcceptor {
    // Load the legacy provider so the server can use weak ciphers too
    load_legacy_provider();

    // Build from scratch — no mozilla presets that restrict ciphers/versions.
    // mozilla_intermediate sets SSL options that can disable TLS 1.3.
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_security_level(0);
    // Clear ALL version restrictions and options
    builder.set_min_proto_version(None).unwrap();
    builder.set_max_proto_version(None).unwrap();
    // Remove any SSL options that might disable specific TLS versions
    builder.clear_options(
        SslOptions::NO_TLSV1_3
            | SslOptions::NO_TLSV1_2
            | SslOptions::NO_TLSV1_1
            | SslOptions::NO_TLSV1,
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

    let (pkey, cert) = generate_self_signed();
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
        let acceptor = build_acceptor(&config);

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
