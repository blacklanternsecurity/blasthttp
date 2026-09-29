// Does our JA4 agree with everyone else's?
//
// The baseline tests pin what we send, but a JA4 implementation that is wrong
// in a self-consistent way would pass all of them and still be useless for
// comparing against a browser. This checks the algorithm itself against a
// captured real-browser ClientHello whose JA4 is published.
//
// Reference data is the Chrome 150 signature from lexiforest/curl-impersonate,
// `tests/signatures/chrome_150.0.7871.127_macOS.yaml` (MIT licensed, copyright
// the curl_cffi developers). Its JA4 is corroborated by four independent
// projects across three different fingerprinting services, which is about as
// much agreement as this area offers.
//
// Worth knowing when adding vectors: fingerprint values are not portable
// between calculators. One handshake observed by seven services produced three
// different JA3 hashes and two different JA4s. Only add a vector whose expected
// value has independent corroboration, or this file starts asserting one
// service's quirks.

mod support;

use support::tls_server::CapturedHello;

/// GREASE placeholder. Which of the sixteen values appears does not matter,
/// since every one of them is stripped before hashing.
const GREASE: u16 = 0x0a0a;

/// Chrome 150 on macOS, as captured by curl-impersonate.
fn chrome_150() -> CapturedHello {
    CapturedHello {
        // Modern hellos pin this at TLS 1.2 and put the real list in
        // supported_versions.
        legacy_version: 0x0303,
        ciphers: vec![
            GREASE, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156,
            157, 47, 53,
        ],
        // In the order Chrome sent them. Chrome permutes this per connection,
        // which is exactly why JA4 sorts before hashing and why the order here
        // does not affect the result.
        extensions: vec![
            GREASE, 0x44cd, 0x002d, 0x001b, 0x0033, 0x002b, 0xff01, 0xfe0d, 0x0017, 0x000b, 0x0005,
            0x0023, 0x000a, 0x0012, 0x0010, 0x000d, 0x0000, 0x1a1a,
        ],
        groups: vec![GREASE, 4588, 29, 23, 24],
        // The first three are ML-DSA, new in recent Chrome. Order is
        // significant: JA4 does not sort this list.
        sig_algs: vec![
            2308, 2309, 2310, 1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537,
        ],
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        supported_versions: vec![GREASE, 0x0304, 0x0303],
        has_sni: true,
    }
}

#[test]
fn test_ja4_matches_published_chrome_150() {
    const PUBLISHED: &str = "t13d1516h2_8daaf6152771_806a8c22fdea";

    let computed = support::ja4::ja4(&chrome_150());

    assert_eq!(
        computed,
        PUBLISHED,
        "JA4 disagrees with the published value for Chrome 150.\n  raw: {}",
        support::ja4::ja4_raw(&chrome_150()),
    );
}

#[test]
fn test_ja4_header_decodes_as_expected() {
    // Spelled out so a failure says which field moved rather than just that a
    // string differs. 16 ciphers and 18 extensions were sent; one and two of
    // those are GREASE, giving the 15 and 16 in the header.
    let hello = chrome_150();
    let computed = support::ja4::ja4(&hello);
    let header = computed.split('_').next().unwrap();

    assert_eq!(&header[0..1], "t", "protocol should be TCP");
    assert_eq!(
        &header[1..3],
        "13",
        "supported_versions tops out at TLS 1.3"
    );
    assert_eq!(&header[3..4], "d", "SNI was present");
    assert_eq!(&header[4..6], "15", "16 ciphers less 1 GREASE");
    assert_eq!(&header[6..8], "16", "18 extensions less 2 GREASE");
    assert_eq!(&header[8..10], "h2", "first and last char of first ALPN");
}

#[test]
fn test_extension_order_does_not_change_ja4() {
    // The property the whole stealth plan rests on. Chrome shuffles its
    // extension order every connection, so if ordering moved the hash, no
    // stable Chrome JA4 could exist. It also means our inability to control
    // extension order under OpenSSL costs us nothing on this metric.
    let mut shuffled = chrome_150();
    shuffled.extensions.reverse();

    assert_eq!(
        support::ja4::ja4(&chrome_150()),
        support::ja4::ja4(&shuffled),
        "reversing the extension order changed the JA4"
    );
}

#[test]
fn test_grease_does_not_change_ja4() {
    // The other half of the same argument: GREASE is stripped, so not emitting
    // any costs nothing here either. It is still visible to anything reading
    // the raw hello, which is tracked separately in fingerprint_baseline.rs.
    let mut without = chrome_150();
    without.ciphers.retain(|c| !support::ja4::is_grease(*c));
    without.extensions.retain(|e| !support::ja4::is_grease(*e));
    without.groups.retain(|g| !support::ja4::is_grease(*g));
    without
        .supported_versions
        .retain(|v| !support::ja4::is_grease(*v));

    assert_eq!(
        support::ja4::ja4(&chrome_150()),
        support::ja4::ja4(&without),
        "removing GREASE changed the JA4"
    );
}

#[test]
fn test_sig_alg_order_does_change_ja4() {
    // Signature algorithms are the one list JA4 leaves in the order sent, so
    // a profile that gets the values right and the order wrong still fails to
    // match. Guards against anyone "tidying up" by sorting them.
    let mut reordered = chrome_150();
    reordered.sig_algs.reverse();

    assert_ne!(
        support::ja4::ja4(&chrome_150()),
        support::ja4::ja4(&reordered),
        "signature algorithm order should be significant"
    );
}
