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

    // The default is now `modern`: 11 cipher suites, TLS 1.2 and 1.3 only.
    //
    // 12 extensions rather than 11, because a TLS 1.2 floor trips our OpenSSL
    // patch into sending renegotiation_info (0xff01) instead of the SCSV. That
    // is the intended behaviour of the patch and not incidental: a client
    // whose floor is 1.2 signals the modern way, and one willing to speak
    // older protocols keeps the SCSV.
    //
    // Reads `t13i` rather than `t13d` because this server is addressed by IP,
    // so no SNI is sent. Chrome 131 for contrast is t13d1516h2.
    const EXPECTED: &str = "t13i1112h2";

    let header = actual.split('_').next().unwrap_or_default();
    assert_eq!(
        header,
        EXPECTED,
        "default JA4 header moved.\n  was: {}\n  now: {}\n  raw: {}",
        EXPECTED,
        header,
        support::ja4::ja4_raw(&hello),
    );
}

#[tokio::test]
async fn test_compatibility_ja4_is_pinned() {
    // What the default used to be, and still is when asked for by name. This
    // pin is `compatibility`'s specification along with legacy_default.rs: if
    // it moves, the profile has stopped being a faithful transcription of what
    // shipped before profiles existed.
    //
    // 105 suites renders as 99 because the JA4 count field is two digits and
    // the spec caps it. Worth knowing on its own: past 99, JA4 cannot tell 105
    // from 200.
    //
    // Reads `t13d` and 12 extensions, not `t13i` and 11, because this capture
    // addresses the server by hostname so SNI is sent. The IP-addressed
    // equivalent is t13i9911h2.
    let hello = capture_profile_hello("compatibility").await;
    let header = support::ja4::ja4(&hello);
    let header = header.split('_').next().unwrap_or_default();

    assert_eq!(
        header,
        "t13d9912h2",
        "compatibility JA4 moved.\n  raw: {}",
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
async fn test_compatibility_offers_legacy_protocol_versions() {
    // SSLv3 through TLS 1.3 all offered, which is what makes an ancient server
    // reachable. No longer what an unconfigured request sends: the default is
    // `modern`, and a legacy server is reached by the ladder falling back to
    // this profile instead.
    let hello = capture_profile_hello("compatibility").await;

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
    // Extensions the browser profile sends and the default does not. Named
    // here so the gap stays legible.
    //
    // renegotiation_info (0xff01) is deliberately absent from this list: the
    // default now sends it, because `modern` sets a TLS 1.2 floor and the
    // OpenSSL patch keys on exactly that. It is not a browser-only extension,
    // it is what any client with a modern floor should send.
    let hello = capture_default_hello().await;

    for (ext, name) in [
        (0x0005u16, "status_request"),
        (0x0012, "signed_certificate_timestamp"),
        (0x001b, "compress_certificate"),
        (0x44cd, "application_settings (ALPS)"),
        (0xfe0d, "encrypted_client_hello"),
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
async fn test_chrome_profile_ja4_is_pinned() {
    let hello = capture_profile_hello("chrome").await;
    let got = support::ja4::ja4(&hello);

    // Chrome 131 and 124, confirmed against tls.peet.ws, is
    // t13d1516h2_8daaf6152771_02713d6af862.
    //
    // The cipher segment matches it exactly. The extension count does not, and
    // is not meant to: three of Chrome's extensions are deliberately not sent
    // because advertising them broke real sites. See add_browser_extensions()
    // for which and why.
    //
    // Worth recording next to the pin, because it is the finding that shaped
    // the whole approach: this non-matching JA4 is enough to turn akamai.com
    // from a hard 403 into a 200 with a real session. Exact parity was not the
    // bar. A client that connects beats one that matches a hash and cannot.
    const EXPECTED: &str = "t13d1513h2_8daaf6152771_1eb89897b454";

    assert_eq!(
        got,
        EXPECTED,
        "Chrome profile JA4 moved.\n  raw: {}",
        support::ja4::ja4_raw(&hello),
    );
}

#[tokio::test]
async fn test_chrome_profile_cipher_list_matches_chrome_exactly() {
    // The cipher segment is the one part that does match Chrome, and it only
    // does because of the OpenSSL patch: stock OpenSSL appends
    // TLS_EMPTY_RENEGOTIATION_INFO_SCSV to the list, which no browser sends,
    // and that one extra suite changed the hash. Guarded separately so a
    // regression there is unmistakable.
    let hello = capture_profile_hello("chrome").await;
    let got = support::ja4::ja4(&hello);
    let cipher_hash = got.split('_').nth(1).unwrap_or_default();

    assert_eq!(
        cipher_hash, "8daaf6152771",
        "cipher list no longer matches Chrome 131"
    );
    assert!(
        !hello.ciphers.contains(&0x00ff),
        "the renegotiation SCSV is back in the cipher list: {:04x?}",
        hello.ciphers
    );
}

#[tokio::test]
async fn test_chrome_profile_sends_renegotiation_info() {
    // The other half of the same patch. OpenSSL sends the SCSV precisely when
    // it is not sending this extension, so these two tests fail together.
    let hello = capture_profile_hello("chrome").await;
    assert!(
        hello.extensions.contains(&0xff01),
        "renegotiation_info missing, so the OpenSSL patch is not in this build"
    );
}

#[tokio::test]
async fn test_chrome_profile_drops_non_browser_extensions() {
    // padding and encrypt_then_mac are OpenSSL habits no browser has.
    let hello = capture_profile_hello("chrome").await;
    for (ext, name) in [(0x0015u16, "padding"), (0x0016, "encrypt_then_mac")] {
        assert!(
            !hello.extensions.contains(&ext),
            "{} ({:#06x}) should not be sent under a browser profile",
            name,
            ext
        );
    }
}

#[tokio::test]
async fn test_compat_path_keeps_the_scsv() {
    // The OpenSSL patch is conditioned on the TLS floor, so `compatibility`,
    // which sets no floor, stays byte-identical to stock OpenSSL: the SCSV
    // goes out and renegotiation_info does not. `modern` is the other side of
    // that same condition, and test_default_ja4_is_pinned covers it.
    let hello = capture_profile_hello("compatibility").await;
    assert!(
        hello.ciphers.contains(&0x00ff),
        "compatibility path lost the SCSV, so the patch is too broad"
    );
    assert!(
        !hello.extensions.contains(&0xff01),
        "compatibility path gained renegotiation_info, so the patch is too broad"
    );
}
