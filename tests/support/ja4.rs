// JA4 over a captured ClientHello.
//
// JA4 is FoxIO's TLS client fingerprint (BSD-3; the JA4+ family that includes
// JA4H is under a separate non-commercial licence and is deliberately not
// implemented here). It replaced JA3 because JA3 preserves ordering and counts
// GREASE, and Chrome shuffles its extension order and emits fresh GREASE on
// every connection, so one Chrome build produces a different JA3 per
// handshake. JA4 sorts and strips, so it holds still.
//
// That property is why this is the metric worth gating on: extension order and
// GREASE are the two things OpenSSL cannot control, and JA4 ignores both.
//
//     JA4 = <a>_<b>_<c>
//       a  protocol, version, SNI, cipher count, extension count, ALPN
//       b  first 12 hex of sha256 over the sorted cipher list
//       c  first 12 hex of sha256 over the sorted extension list, then the
//          signature algorithms in the order sent
//
// Operates on a `CapturedHello` from the sibling `tls_server` module.

use super::tls_server::CapturedHello;

/// RFC 8701 GREASE values: both bytes equal, low nibble `a`.
/// 0x0a0a, 0x1a1a, ... 0xfafa.
pub fn is_grease(v: u16) -> bool {
    (v >> 8) == (v & 0x00ff) && (v & 0x000f) == 0x000a
}

fn strip_grease(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|v| !is_grease(*v)).collect()
}

fn sha256_prefix12(input: &str) -> String {
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), input.as_bytes())
        .expect("sha256 of an in-memory string cannot fail");
    digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()[..12]
        .to_string()
}

/// A list that contributes nothing hashes to zeros rather than to the hash of
/// an empty string, which is what the spec calls for.
fn hash_list(values: &[u16]) -> String {
    if values.is_empty() {
        return "000000000000".to_string();
    }
    let joined = values
        .iter()
        .map(|v| format!("{:04x}", v))
        .collect::<Vec<_>>()
        .join(",");
    sha256_prefix12(&joined)
}

/// Two characters naming the negotiated TLS version.
fn version_code(hello: &CapturedHello) -> &'static str {
    // `supported_versions` is authoritative when present. The legacy field is
    // pinned at TLS 1.2 on any modern hello regardless of what is really
    // offered, so reading it alone would call every TLS 1.3 client 1.2.
    let versions = strip_grease(&hello.supported_versions);
    let highest = versions
        .iter()
        .copied()
        .max()
        .unwrap_or(hello.legacy_version);
    match highest {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

/// First and last character of the first ALPN value: `h2` stays `h2`,
/// `http/1.1` becomes `h1`. `00` when no ALPN was offered.
fn alpn_code(hello: &CapturedHello) -> String {
    match hello.alpn.first() {
        None => "00".to_string(),
        Some(first) => {
            let chars: Vec<char> = first.chars().collect();
            match (chars.first(), chars.last()) {
                (Some(a), Some(z)) if a.is_ascii() && z.is_ascii() => format!("{}{}", a, z),
                _ => "99".to_string(),
            }
        }
    }
}

/// Compute the JA4 string for a captured hello.
pub fn ja4(hello: &CapturedHello) -> String {
    let ciphers = strip_grease(&hello.ciphers);
    let extensions = strip_grease(&hello.extensions);

    // Counts are capped at 99 because the field is two digits wide.
    let cipher_count = ciphers.len().min(99);
    let ext_count = extensions.len().min(99);

    let a = format!(
        "t{}{}{:02}{:02}{}",
        version_code(hello),
        if hello.has_sni { "d" } else { "i" },
        cipher_count,
        ext_count,
        alpn_code(hello),
    );

    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let b = hash_list(&sorted_ciphers);

    // server_name and ALPN are counted in the header but left out of the hash,
    // since both vary with the request rather than with the client.
    let mut sorted_exts: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|e| *e != 0x0000 && *e != 0x0010)
        .collect();
    sorted_exts.sort_unstable();

    // Signature algorithms keep the order they were sent in, and GREASE has to
    // come out of them too. Chrome 152 puts a fresh greased value at the head
    // of this list every handshake, so an implementation that keeps it reports
    // a different third segment on every connection.
    let sig_algs = strip_grease(&hello.sig_algs);

    let c = if sorted_exts.is_empty() {
        "000000000000".to_string()
    } else {
        let ext_part = sorted_exts
            .iter()
            .map(|v| format!("{:04x}", v))
            .collect::<Vec<_>>()
            .join(",");
        let sig_part = sig_algs
            .iter()
            .map(|v| format!("{:04x}", v))
            .collect::<Vec<_>>()
            .join(",");
        sha256_prefix12(&format!("{}_{}", ext_part, sig_part))
    };

    format!("{}_{}_{}", a, b, c)
}

/// The readable form: same fields, nothing hashed. What you actually want when
/// a fingerprint moved and you need to know which byte did it.
pub fn ja4_raw(hello: &CapturedHello) -> String {
    let ciphers = strip_grease(&hello.ciphers);
    let extensions = strip_grease(&hello.extensions);

    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let mut sorted_exts: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|e| *e != 0x0000 && *e != 0x0010)
        .collect();
    sorted_exts.sort_unstable();

    let hex = |vs: &[u16]| {
        vs.iter()
            .map(|v| format!("{:04x}", v))
            .collect::<Vec<_>>()
            .join(",")
    };

    format!(
        "t{}{}{:02}{:02}{}_{}_{}_{}",
        version_code(hello),
        if hello.has_sni { "d" } else { "i" },
        ciphers.len().min(99),
        extensions.len().min(99),
        alpn_code(hello),
        hex(&sorted_ciphers),
        hex(&sorted_exts),
        hex(&strip_grease(&hello.sig_algs)),
    )
}
