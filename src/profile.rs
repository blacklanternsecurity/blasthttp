//! Browser profiles: what a real browser puts on the wire.
//!
//! A profile is data, not code, because browsers ship every few weeks and a
//! profile that has to be rewritten each time will not be kept current.
//!
//! The rule that shapes all of this: a profile has to be applied whole or not
//! at all. Sending browser headers over a non-browser handshake is worse than
//! sending honest ones, because a client claiming to be Chrome whose first
//! packet says otherwise has stated something checkably false, and that is a
//! stronger signal than merely being unfamiliar. Measured: `udemy.com` returns
//! 200 to an honest curl and 403 with `cf-mitigated: challenge` to the same
//! client wearing only a Chrome User-Agent.

/// The TLS half of a browser profile.
///
/// Fields map onto the OpenSSL calls that set them. TLS 1.3 suites and TLS 1.2
/// suites are separate because OpenSSL configures them through different
/// functions: `SSL_CTX_set_ciphersuites` and `SSL_CTX_set_cipher_list`. Setting
/// only the latter, which is all blasthttp did before this, leaves the 1.3
/// suites at OpenSSL's defaults in OpenSSL's order.
#[derive(Debug, Clone, Copy)]
pub struct TlsProfile {
    /// TLS 1.3 suites, in order, colon separated (`SSL_CTX_set_ciphersuites`).
    pub ciphersuites: &'static str,
    /// TLS 1.2 and below, in order, colon separated (`SSL_CTX_set_cipher_list`).
    pub cipher_list: &'static str,
    /// Signature algorithms, in order. JA4 hashes this list as sent rather
    /// than sorted, so the order is part of the fingerprint.
    pub sigalgs: &'static str,
    /// Supported groups, in order. Note these do not affect JA4: only the
    /// presence of the extension is counted, not its contents. They are still
    /// visible to anything reading the raw hello.
    pub groups: &'static str,
    pub min_version: &'static str,
    pub max_version: &'static str,
    pub alpn: &'static [&'static str],
}

/// A complete profile: TLS, plus the HTTP layers that have to agree with it.
#[derive(Debug, Clone, Copy)]
pub struct BrowserProfile {
    pub name: &'static str,
    pub tls: TlsProfile,
    /// Default request headers in the order the browser sends them. HTTP/1.1
    /// header order is preserved by this client, so this is the order that
    /// goes on the wire.
    pub headers: &'static [(&'static str, &'static str)],
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
pub const CHROME_131: BrowserProfile = BrowserProfile {
    name: "chrome131",
    tls: TlsProfile {
        // 1301, 1302, 1303.
        ciphersuites: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
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
        sigalgs: "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:\
                  ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:\
                  RSA-PSS+SHA512:RSA+SHA512",
        // Chrome also offers X25519MLKEM768 (4588) ahead of these, which
        // OpenSSL gained in 3.5 and ours cannot send. It does not affect JA4,
        // but it is visible in the raw hello, and a client claiming to be a
        // current Chrome while offering no post-quantum share is itself worth
        // noticing.
        groups: "X25519:P-256:P-384",
        min_version: "1.2",
        max_version: "1.3",
        alpn: &["h2", "http/1.1"],
    },
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
};

/// Look a profile up by name.
pub fn by_name(name: &str) -> Option<&'static BrowserProfile> {
    match name.to_ascii_lowercase().as_str() {
        // "chrome" tracks the newest profile we can actually reproduce, which
        // is what a caller asking for "chrome" wants.
        "chrome" | "chrome131" => Some(&CHROME_131),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrome_alias_resolves() {
        assert_eq!(by_name("chrome").unwrap().name, "chrome131");
        assert_eq!(by_name("CHROME131").unwrap().name, "chrome131");
        assert!(by_name("netscape").is_none());
    }

    #[test]
    fn test_cipher_counts_match_the_target() {
        // 12 TLS 1.2 suites plus 3 TLS 1.3 suites is the 15 that JA4 counts
        // for Chrome. Getting this wrong moves the JA4 header, so it is worth
        // asserting next to the data rather than only end to end.
        let p = CHROME_131.tls;
        assert_eq!(p.cipher_list.split(':').count(), 12);
        assert_eq!(p.ciphersuites.split(':').count(), 3);
        assert_eq!(p.sigalgs.split(':').count(), 8);
    }

    #[test]
    fn test_headers_are_in_browser_order() {
        // Order is part of the fingerprint, so guard the two ends of it.
        let names: Vec<&str> = CHROME_131.headers.iter().map(|(n, _)| *n).collect();
        assert_eq!(names.first(), Some(&"sec-ch-ua"));
        assert_eq!(names.last(), Some(&"priority"));
        assert!(names.contains(&"sec-fetch-dest"));
    }
}
