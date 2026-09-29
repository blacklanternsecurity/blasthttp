//! Connection profiles: what we put on the wire, and what we claim to be.
//!
//! A profile is data, not code, because browsers ship every few weeks and one
//! that has to be rewritten each time will not be kept current.
//!
//! Profiles differ on two independent axes, which is why a single ladder from
//! "safe" to "aggressive" does not describe them:
//!
//!   breadth  narrow current ciphers  <->  everything, SSLv3 upward
//!   claim    no identity claim       <->  claiming to be a browser
//!
//! | profile | breadth | claim | for |
//! |---|---|---|---|
//! | [`COMPATIBILITY`] | everything | honest | ancient servers, TLS enumeration |
//! | [`MODERN`] | narrow | honest | ordinary traffic |
//! | [`CHROME_131`] | Chrome's list | Chrome | hosts that reward imitation |
//!
//! Two measured findings shape this.
//!
//! A profile must be applied whole or not at all. Browser headers over a
//! non-browser handshake are worse than honest ones: `udemy.com` returns 200
//! to an honest curl and 403 with `cf-mitigated: challenge` to the same client
//! wearing only a Chrome User-Agent.
//!
//! And claiming to be a browser is not free. The User-Agent is not what gets
//! scored, it selects which scoring applies: claim a browser and the client is
//! checked against the claim. On `priceline.com`, plain blasthttp gets through
//! 3/3 and our Chrome profile 0/3, while curl_cffi, whose imitation survives
//! the check, gets 3/3. So `MODERN` exists to be unremarkable without
//! inviting that inspection.

/// The TLS half of a browser profile.
///
/// Fields map onto the OpenSSL calls that set them. TLS 1.3 suites and TLS 1.2
/// suites are separate because OpenSSL configures them through different
/// functions: `SSL_CTX_set_ciphersuites` and `SSL_CTX_set_cipher_list`. Setting
/// only the latter, which is all blasthttp did before this, leaves the 1.3
/// suites at OpenSSL's defaults in OpenSSL's order.
#[derive(Debug, Clone, Copy)]
pub struct TlsProfile {
    /// TLS 1.3 suites, in order, colon separated
    /// (`SSL_CTX_set_ciphersuites`). `None` leaves OpenSSL's own list and
    /// order, which is what a profile wanting to look like an ordinary
    /// OpenSSL client should do.
    pub ciphersuites: Option<&'static str>,
    /// TLS 1.2 and below, in order, colon separated (`SSL_CTX_set_cipher_list`).
    pub cipher_list: &'static str,
    /// Signature algorithms, in order. JA4 hashes this list as sent rather
    /// than sorted, so the order is part of the fingerprint. `None` leaves
    /// OpenSSL's.
    pub sigalgs: Option<&'static str>,
    /// Supported groups, in order. These do not affect JA4, which counts only
    /// the presence of the extension and not its contents, but they are
    /// visible to anything reading the raw hello. `None` leaves OpenSSL's.
    pub groups: Option<&'static str>,
    /// `None` leaves the floor and ceiling entirely to OpenSSL, which at
    /// security level 0 with NO_SSLV3 cleared means SSLv3 through TLS 1.3.
    pub min_version: Option<&'static str>,
    pub max_version: Option<&'static str>,
    pub alpn: &'static [&'static str],
    /// Send the extensions a browser sends and suppress the two it does not.
    ///
    /// An explicit field rather than "is a profile set", which is how this
    /// worked before there was more than one profile. Left implicit, naming
    /// today's behaviour as a profile would have switched certificate-status
    /// requests and SCT on, and padding and encrypt_then_mac off, for the very
    /// configuration that is supposed to be byte-identical to what shipped.
    pub browser_extensions: bool,
}

/// The HTTP/2 half of a profile.
///
/// Values are what the browser puts in its SETTINGS frame and its
/// connection-level WINDOW_UPDATE, which together make up most of what is
/// commonly called the Akamai HTTP/2 fingerprint.
///
/// Two fields of that fingerprint are deliberately absent because our stack
/// cannot reach them without forking dependencies:
///
///   HEADER_TABLE_SIZE (setting 1): hyper carries it internally but
///   hyper-util does not expose it, so there is no way to set it from here.
///
///   Pseudo-header order: `h2` hardcodes method, scheme, authority, path in
///   `Iter::next()`, and Chrome sends method, authority, scheme, path.
///   Changing it means forking h2, hyper and hyper-util, since each layer
///   translates a fixed set of options rather than passing them through.
#[derive(Debug, Clone, Copy)]
pub struct Http2Profile {
    /// SETTINGS 4, INITIAL_WINDOW_SIZE.
    pub initial_stream_window: u32,
    /// The connection window. The WINDOW_UPDATE a browser sends is this minus
    /// the protocol default of 65535, so Chrome's 15663105 increment comes
    /// from asking for 15 MiB.
    pub initial_connection_window: u32,
    /// SETTINGS 6, MAX_HEADER_LIST_SIZE.
    pub max_header_list_size: u32,
    /// SETTINGS 5, MAX_FRAME_SIZE. `None` leaves it out, which is what Chrome
    /// does; our default sends 16384 and Chrome sends nothing.
    pub max_frame_size: Option<u32>,
}

/// A complete profile: TLS, plus the HTTP layers that have to agree with it.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionProfile {
    pub name: &'static str,
    pub tls: TlsProfile,
    /// `None` leaves hyper-util's HTTP/2 defaults, which match no browser but
    /// are the right answer for a profile not pretending to be one.
    pub http2: Option<Http2Profile>,
    /// Default request headers, in the order they go on the wire. HTTP/1.1
    /// header order is preserved by this client, so this ordering is real.
    /// Empty means the client's own minimal defaults.
    pub headers: &'static [(&'static str, &'static str)],
    /// Whether this profile claims to be a browser.
    ///
    /// The axis the ladder moves along on a policy block, and the reason it is
    /// a field rather than something inferred from the headers: what matters
    /// is whether we invited a browser-shaped inspection, not which browser we
    /// named.
    pub claims_browser: bool,
}

/// Chrome 131 on Windows.
///
/// Chosen over a newer Chrome deliberately. Chrome 133 and later sign with
/// ML-DSA (signature algorithms 0x0904 through 0x0906), which OpenSSL 3.3.2
/// does not know, so its signature_algorithms list cannot be reproduced and
/// its JA4 is out of reach. Chrome 131's list is entirely standard.
///
/// The cipher and extension sets are identical between Chrome 124 and 150, so
/// this is not a stale profile in the way the version number suggests; only
/// the signature algorithms moved. Both Chrome 131 and 124 produce
/// `t13d1516h2_8daaf6152771_02713d6af862`.
pub const CHROME_131: ConnectionProfile = ConnectionProfile {
    name: "chrome131",
    tls: TlsProfile {
        // 1301, 1302, 1303.
        ciphersuites: Some(
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
        ),
        // c02b, c02f, c02c, c030, cca9, cca8, c013, c014, 009c, 009d, 002f, 0035.
        cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                      ECDHE-RSA-AES128-GCM-SHA256:\
                      ECDHE-ECDSA-AES256-GCM-SHA384:\
                      ECDHE-RSA-AES256-GCM-SHA384:\
                      ECDHE-ECDSA-CHACHA20-POLY1305:\
                      ECDHE-RSA-CHACHA20-POLY1305:\
                      ECDHE-RSA-AES128-SHA:\
                      ECDHE-RSA-AES256-SHA:\
                      AES128-GCM-SHA256:\
                      AES256-GCM-SHA384:\
                      AES128-SHA:\
                      AES256-SHA",
        // 0403, 0804, 0401, 0503, 0805, 0501, 0806, 0601, in that order.
        sigalgs: Some(
            "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:\
             ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:\
             RSA-PSS+SHA512:RSA+SHA512",
        ),
        // Chrome also offers X25519MLKEM768 (4588) ahead of these, which
        // OpenSSL gained in 3.5 and ours cannot send. It does not affect JA4,
        // but it is visible in the raw hello, and a client claiming to be a
        // current Chrome while offering no post-quantum share is itself worth
        // noticing.
        groups: Some("X25519:P-256:P-384"),
        min_version: Some("1.2"),
        max_version: Some("1.3"),
        alpn: &["h2", "http/1.1"],
        browser_extensions: true,
    },
    // Chrome's Akamai fingerprint is
    // 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p. ENABLE_PUSH is
    // already 0 because hyper always disables push.
    http2: Some(Http2Profile {
        initial_stream_window: 6_291_456,
        // 15 MiB. The WINDOW_UPDATE that results is 15728640 - 65535 =
        // 15663105, which is what Chrome sends.
        initial_connection_window: 15_728_640,
        max_header_list_size: 262_144,
        max_frame_size: None,
    }),
    headers: &[
        (
            "sec-ch-ua",
            "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        ),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", "\"Windows\""),
        ("upgrade-insecure-requests", "1"),
        (
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        ),
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,\
             image/avif,image/webp,image/apng,*/*;q=0.8,\
             application/signed-exchange;v=b3;q=0.7",
        ),
        ("sec-fetch-site", "none"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-user", "?1"),
        ("sec-fetch-dest", "document"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("accept-language", "en-US,en;q=0.9"),
        ("priority", "u=0, i"),
    ],
    claims_browser: true,
};

/// Everything, SSLv3 upward, with an honest User-Agent.
///
/// A faithful transcription of what blasthttp sent before profiles existed,
/// and it has to stay that way: `tests/legacy_default.rs` and
/// `test_compat_path_keeps_the_scsv` are its specification. Every `None` here
/// is deliberate, meaning "leave OpenSSL alone", because that is what the
/// unnamed default did.
///
/// Honest but conspicuous. The cipher list resolves to 105 suites, and the
/// resulting hello has never been observed in roughly 17 billion connections
/// recorded by tlsfingerprint.io. That is the cost of reaching a server from
/// 2003, and it is why it is no longer the thing you get by accident.
pub const COMPATIBILITY: ConnectionProfile = ConnectionProfile {
    name: "compatibility",
    tls: TlsProfile {
        ciphersuites: None,
        // Every suite the build provides except the eNULL ones. Includes the
        // aNULL suites, which skip authentication: worth reaching for a
        // scanner, and this client already does not verify certificates by
        // default, so they give up nothing that was being enforced.
        cipher_list: "ALL",
        sigalgs: None,
        groups: None,
        min_version: None,
        max_version: None,
        alpn: &["h2", "http/1.1"],
        browser_extensions: false,
    },
    http2: None,
    headers: &[],
    claims_browser: false,
};

/// Narrow current ciphers, no identity claim.
///
/// Sits between the other two: `COMPATIBILITY` is honest but offers 105 suites
/// and every protocol version back to SSLv3; `CHROME_131` looks ordinary but
/// makes a claim it cannot fully back. This offers a current, boring cipher
/// list and claims nothing.
///
/// What it buys, measured:
///
///   JA4 goes from `t13d10512h2` to `t13d1113h2`. Eleven suites instead of a
///   hundred and five, which is a shape plenty of software has, where 105 is
///   a shape essentially nothing has.
///
///   SSLv3, TLS 1.0 and TLS 1.1 stop being offered. A client advertising
///   SSLv3 in 2026 is conspicuous on its own.
///
/// What it does NOT buy, also measured, and worth recording because it was the
/// original argument for this profile: it is not "unremarkable in real
/// traffic". Checked against tlsfingerprint.io, which indexes roughly 17
/// billion observed connections, all three of our profiles come back never
/// seen, `MODERN` included. Narrowing the cipher list fixes the JA4 and does
/// nothing for the rest of the hello, which stays distinctive for reasons
/// OpenSSL gives us no way to change: no GREASE anywhere, and extensions in
/// OpenSSL's fixed order rather than a browser's shuffled one.
///
/// So the case for it rests on the JA4 and the version floor, not on blending
/// in. Blending in is not available on this TLS stack.
///
/// It cannot reach a server that speaks only deprecated ciphers. That is what
/// falling back to `COMPATIBILITY` is for.
pub const MODERN: ConnectionProfile = ConnectionProfile {
    name: "modern",
    tls: TlsProfile {
        ciphersuites: Some(
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
        ),
        // ECDHE with AEAD, which is what current guidance and every modern
        // library converge on. Twelve suites rather than a hundred and five.
        cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                      ECDHE-RSA-AES128-GCM-SHA256:\
                      ECDHE-ECDSA-AES256-GCM-SHA384:\
                      ECDHE-RSA-AES256-GCM-SHA384:\
                      ECDHE-ECDSA-CHACHA20-POLY1305:\
                      ECDHE-RSA-CHACHA20-POLY1305:\
                      DHE-RSA-AES128-GCM-SHA256:\
                      DHE-RSA-AES256-GCM-SHA384",
        sigalgs: None,
        groups: Some("X25519:P-256:P-384:P-521"),
        // No SSLv3, TLS 1.0 or 1.1. Offering them is one of the louder things
        // the old default did.
        min_version: Some("1.2"),
        max_version: Some("1.3"),
        alpn: &["h2", "http/1.1"],
        browser_extensions: false,
    },
    http2: None,
    headers: &[],
    claims_browser: false,
};

/// Look a profile up by name.
///
/// Unknown names are an error rather than silently resolving to the default.
/// They used to: a typo bought you whatever the default was, with nothing said
/// about it, which is a poor trade once the choice of profile decides whether
/// a request is inspected.
pub fn by_name(name: &str) -> Result<&'static ConnectionProfile, String> {
    match name.to_ascii_lowercase().as_str() {
        "compatibility" | "compat" => Ok(&COMPATIBILITY),
        "modern" => Ok(&MODERN),
        // "chrome" tracks the newest Chrome we can actually reproduce, which
        // is what a caller asking for "chrome" wants.
        "chrome" | "chrome131" | "browser" => Ok(&CHROME_131),
        other => Err(format!(
            "unknown profile '{}' (known: compatibility, modern, chrome)",
            other
        )),
    }
}

/// The profile a request gets when it does not name one.
pub fn default_profile() -> &'static ConnectionProfile {
    &COMPATIBILITY
}

#[cfg(test)]
// These assertions are deliberately about constants: the profiles are data,
// and the point of the tests is that editing that data fails loudly. Clippy
// is right that they fold at compile time and wrong that this makes them
// pointless.
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_resolves_and_rejects() {
        assert_eq!(by_name("chrome").unwrap().name, "chrome131");
        assert_eq!(by_name("CHROME131").unwrap().name, "chrome131");
        assert_eq!(by_name("modern").unwrap().name, "modern");
        assert_eq!(by_name("compat").unwrap().name, "compatibility");

        // An unknown name is an error, not a silent fallback. It used to be a
        // fallback, which meant a typo bought you the default with nothing
        // said about it.
        let err = by_name("netscape").unwrap_err();
        assert!(
            err.contains("netscape"),
            "error should name the input: {err}"
        );
        assert!(
            err.contains("compatibility"),
            "error should list the options"
        );
    }

    #[test]
    fn test_compatibility_leaves_openssl_alone() {
        // This profile has to stay byte-identical to what shipped before
        // profiles existed, and every `None` is how that is expressed.
        // `tests/legacy_default.rs` is the end-to-end proof; this is the
        // cheap guard that catches an accidental edit.
        let c = COMPATIBILITY.tls;
        assert_eq!(c.cipher_list, "ALL");
        assert!(c.ciphersuites.is_none(), "would reorder the TLS 1.3 suites");
        assert!(c.sigalgs.is_none());
        assert!(c.groups.is_none());
        assert!(
            c.min_version.is_none() && c.max_version.is_none(),
            "a version floor would put SSLv3 and TLS 1.0 out of reach"
        );
        assert!(
            !c.browser_extensions,
            "browser extensions would add SCT and status_request and drop \
             padding and encrypt_then_mac, none of which the old default did"
        );
        assert!(
            COMPATIBILITY.http2.is_none(),
            "would change the SETTINGS frame"
        );
        assert!(COMPATIBILITY.headers.is_empty());
        assert!(!COMPATIBILITY.claims_browser);
    }

    #[test]
    fn test_modern_is_narrow_and_honest() {
        let m = MODERN.tls;
        // The point of this profile: a short list instead of 105 suites.
        assert_eq!(m.cipher_list.split(':').count(), 8);
        assert_eq!(m.ciphersuites.unwrap().split(':').count(), 3);
        assert_eq!(m.min_version, Some("1.2"), "no SSLv3, TLS 1.0 or 1.1");
        assert!(
            !m.browser_extensions && !MODERN.claims_browser && MODERN.headers.is_empty(),
            "modern must not claim to be a browser; that is the whole \
             difference between it and chrome131"
        );
    }

    #[test]
    fn test_chrome_matches_the_target_shape() {
        // 12 TLS 1.2 suites plus 3 TLS 1.3 suites is the 15 JA4 counts for
        // Chrome. Getting this wrong moves the JA4 header.
        let c = CHROME_131.tls;
        assert_eq!(c.cipher_list.split(':').count(), 12);
        assert_eq!(c.ciphersuites.unwrap().split(':').count(), 3);
        assert_eq!(c.sigalgs.unwrap().split(':').count(), 8);
        assert!(c.browser_extensions);
        assert!(CHROME_131.claims_browser);
        assert!(CHROME_131.http2.is_some());
    }

    #[test]
    fn test_chrome_headers_are_in_browser_order() {
        // Order is part of the fingerprint, so guard both ends of it.
        let names: Vec<&str> = CHROME_131.headers.iter().map(|(n, _)| *n).collect();
        assert_eq!(names.first(), Some(&"sec-ch-ua"));
        assert_eq!(names.last(), Some(&"priority"));
        assert!(names.contains(&"sec-fetch-dest"));
    }

    #[test]
    fn test_only_chrome_claims_to_be_a_browser() {
        // The axis the ladder moves along on a policy block.
        assert!(!COMPATIBILITY.claims_browser);
        assert!(!MODERN.claims_browser);
        assert!(CHROME_131.claims_browser);
    }
}
