// What our ClientHello actually looks like, measured offline.
//
// These tests stand up a local TLS server that records the hello the client
// sends, so the fingerprint can be checked in CI with no network and no
// third-party service. That matters for two reasons: the public fingerprint
// endpoints rate-limit, and several of the ones the ecosystem cites are dead
// or, in one case, now serving a gambling site.
//
// The pinned values below are a regression gate, not an aspiration. Changing
// the TLS configuration is supposed to change them; the point is that it
// cannot happen silently. When one of these fails, read the `ja4_raw` output
// in the failure message, confirm the move was intended, and update the pin.

mod support;

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use support::tls_server::{CapturedHello, TlsServerConfig, TlsTestServer};

/// Make one ordinary request at a capturing server and return what it saw.
async fn capture_default_hello() -> CapturedHello {
    let server = TlsTestServer::start(TlsServerConfig::default()).await;

    let mut config = RequestConfig::new(server.url());
    config.verify_certs = Some(false);
    config.timeout_seconds = Some(5);

    let client = HyperClient::new();
    let _ = client.send(&config).await;

    let hello = server
        .hello
        .lock()
        .expect("hello slot poisoned")
        .clone()
        .expect("server recorded no ClientHello");

    server.shutdown().await;
    hello
}

#[tokio::test]
async fn test_capture_sees_a_plausible_hello() {
    // Guards the harness itself. If capture breaks, every other test in this
    // file would go green against an empty hello and prove nothing.
    let hello = capture_default_hello().await;

    assert!(
        !hello.ciphers.is_empty(),
        "captured no cipher suites, so capture is broken"
    );
    assert!(
        !hello.extensions.is_empty(),
        "captured no extensions, so capture is broken"
    );
    assert!(
        hello.extensions.contains(&0x000d),
        "expected signature_algorithms in the hello"
    );
    assert!(
        !hello.sig_algs.is_empty(),
        "signature_algorithms extension present but parsed empty"
    );
}

#[tokio::test]
async fn test_no_sni_for_an_ip_literal() {
    // The server is addressed by IP, and SNI is not sent for IP literals. This
    // pins the `i` in the JA4 header and is the reason these tests read `t13i`
    // rather than the `t13d` a hostname would give.
    let hello = capture_default_hello().await;
    assert!(
        !hello.has_sni,
        "SNI should be absent when connecting to an IP literal"
    );
}

#[tokio::test]
async fn test_default_ja4_is_pinned() {
    let hello = capture_default_hello().await;
    let actual = support::ja4::ja4(&hello);

    // Current default: the broad legacy cipher list, which is 105 suites.
    // JA4 renders that as `99`, because the count field is two digits wide and
    // the spec caps it. Worth knowing on its own: past 99 suites, JA4 cannot
    // tell 105 from 200, so the header alone stops distinguishing us from any
    // other client with an unreasonable cipher list.
    //
    // The extension count is 11 rather than 12 because this server is
    // addressed by IP, so no SNI is sent. Against a hostname it reads
    // t13d9912h2.
    //
    // Chrome 150 for contrast is t13d1516h2_8daaf6152771_806a8c22fdea: 15
    // ciphers, 16 extensions. Closing that gap is the point of the stealth
    // work, and this pin is how we will see it move.
    const EXPECTED: &str = "t13i9911h2";

    let header = actual.split('_').next().unwrap_or_default();
    assert_eq!(
        header,
        EXPECTED,
        "JA4 header moved.\n  was: {}\n  now: {}\n  raw: {}",
        EXPECTED,
        header,
        support::ja4::ja4_raw(&hello),
    );
}

#[tokio::test]
async fn test_grease_is_absent() {
    // We send no GREASE anywhere, which JA4 ignores but a detector checking
    // the raw hello does not: every modern browser emits GREASE in several
    // places and almost nothing scripted does, so its absence is a cheap and
    // reliable tell. OpenSSL has no API for it at any version.
    //
    // When stealth mode arrives this expectation inverts. Until then it
    // records where we stand.
    let hello = capture_default_hello().await;

    let greased: Vec<u16> = hello
        .ciphers
        .iter()
        .chain(hello.extensions.iter())
        .chain(hello.groups.iter())
        .copied()
        .filter(|v| support::ja4::is_grease(*v))
        .collect();

    assert!(
        greased.is_empty(),
        "expected no GREASE from the OpenSSL stack, found {:04x?}",
        greased
    );
}

#[tokio::test]
async fn test_offers_legacy_protocol_versions() {
    // The companion to the cipher work: SSLv3 through TLS 1.3 are all offered,
    // which is what makes an ancient server reachable without configuration.
    // It is also conspicuous, since a browser offers 1.2 and 1.3 only.
    let hello = capture_default_hello().await;

    for (version, label) in [
        (0x0300u16, "SSLv3"),
        (0x0301, "TLS 1.0"),
        (0x0302, "TLS 1.1"),
        (0x0303, "TLS 1.2"),
        (0x0304, "TLS 1.3"),
    ] {
        assert!(
            hello.supported_versions.contains(&version),
            "{} missing from supported_versions: {:04x?}",
            label,
            hello.supported_versions
        );
    }
}

#[tokio::test]
async fn test_no_browser_only_extensions_yet() {
    // The six extensions a JA4 match against Chrome needs, none of which we
    // send today. Named here so the gap is legible and so each one flips this
    // test as it lands.
    let hello = capture_default_hello().await;

    for (ext, name) in [
        (0x0005u16, "status_request"),
        (0x0012, "signed_certificate_timestamp"),
        (0x001b, "compress_certificate"),
        (0x44cd, "application_settings (ALPS)"),
        (0xfe0d, "encrypted_client_hello"),
        (0xff01, "renegotiation_info"),
    ] {
        assert!(
            !hello.extensions.contains(&ext),
            "{} ({:#06x}) is now sent; stealth work has started, update this test",
            name,
            ext
        );
    }
}

// ── Chrome profile ────────────────────────────────────────────────

/// Capture a hello made with a named profile, addressed by hostname so SNI is
/// sent and the result is comparable with a browser's.
async fn capture_profile_hello(profile: &str) -> CapturedHello {
    let server = TlsTestServer::start(TlsServerConfig::default()).await;
    let url = format!("https://localhost:{}/", server.addr.port());

    let mut config = RequestConfig::new(url);
    config.verify_certs = Some(false);
    config.timeout_seconds = Some(5);
    config.profile = Some(profile.to_string());

    let client = HyperClient::new();
    let _ = client.send(&config).await;

    let hello = server
        .hello
        .lock()
        .expect("hello slot poisoned")
        .clone()
        .expect("server recorded no ClientHello");
    server.shutdown().await;
    hello
}

#[tokio::test]
async fn test_chrome_profile_progress() {
    // Not a pass/fail gate yet. Prints the distance to Chrome 131 so the
    // remaining gap is visible while it is being closed.
    let hello = capture_profile_hello("chrome").await;
    let got = support::ja4::ja4(&hello);

    // Chrome 131 and 124, confirmed against tls.peet.ws.
    const TARGET: &str = "t13d1516h2_8daaf6152771_02713d6af862";

    println!("\n  target: {}", TARGET);
    println!("  actual: {}", got);
    println!("  raw   : {}", support::ja4::ja4_raw(&hello));

    let want: Vec<&str> = TARGET.split('_').collect();
    let have: Vec<&str> = got.split('_').collect();
    for (label, w, h) in [
        ("header", want[0], have[0]),
        ("ciphers", want[1], have[1]),
        ("exts+sigalgs", want[2], have[2]),
    ] {
        println!("  {:13} {}", label, if w == h { "match" } else { "differ" });
    }
}
