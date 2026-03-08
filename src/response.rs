use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub url: String,
    pub status: u16,
    // Vec, not HashMap — HTTP allows duplicate header names (e.g. Set-Cookie)
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing)]
    pub body_bytes: Vec<u8>,
    pub body: String,
    pub elapsed_ms: u64,
    pub redirect_chain: Vec<RedirectHop>,
    /// TLS certificate info extracted during handshake (None for plain HTTP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_info: Option<CertInfo>,
    /// Content hashes for fingerprinting (matches BBOT's hash format)
    pub hash: ResponseHash,
    /// Debug messages collected during the request (for Python-side inspection)
    #[serde(skip_serializing)]
    pub debug_log: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub url: String,
    pub status: u16,
}

/// TLS certificate information extracted during the handshake.
/// Matches what BBOT's sslcert module extracts — CN, SANs, emails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    /// Subject Common Name (CN)
    pub common_name: Option<String>,
    /// Subject Alternative Names (DNS entries)
    pub sans: Vec<String>,
    /// Email addresses from Subject and Issuer
    pub emails: Vec<String>,
    /// Issuer Common Name
    pub issuer: Option<String>,
    /// Not Before (ISO 8601 string)
    pub not_before: Option<String>,
    /// Not After (ISO 8601 string)
    pub not_after: Option<String>,
    /// SHA-256 fingerprint of the certificate (hex encoded)
    pub fingerprint_sha256: Option<String>,
}

/// Response content hashes matching BBOT's response_to_json format.
/// Computed in Rust so Python doesn't have to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseHash {
    pub body_md5: String,
    pub body_mmh3: i32,
    pub body_sha256: String,
    pub header_md5: String,
    pub header_mmh3: i32,
    pub header_sha256: String,
}

impl ResponseHash {
    pub fn compute(body: &[u8], headers: &[(String, String)]) -> Self {
        // Build raw header string matching BBOT's format: "Name: Value\r\n..."
        let raw_headers = headers.iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\r\n");
        let header_bytes = raw_headers.as_bytes();

        ResponseHash {
            body_md5: hex_digest(openssl::hash::MessageDigest::md5(), body),
            body_mmh3: mmh3_32(body),
            body_sha256: hex_digest(openssl::hash::MessageDigest::sha256(), body),
            header_md5: hex_digest(openssl::hash::MessageDigest::md5(), header_bytes),
            header_mmh3: mmh3_32(header_bytes),
            header_sha256: hex_digest(openssl::hash::MessageDigest::sha256(), header_bytes),
        }
    }
}

/// Compute hex-encoded digest using OpenSSL (already linked)
fn hex_digest(algo: openssl::hash::MessageDigest, data: &[u8]) -> String {
    openssl::hash::hash(algo, data)
        .map(|digest| digest.iter().map(|b| format!("{:02x}", b)).collect())
        .unwrap_or_default()
}

/// MurmurHash3 32-bit, matching Python's mmh3.hash() (signed i32, seed=0)
fn mmh3_32(data: &[u8]) -> i32 {
    use std::io::Cursor;
    let mut reader = Cursor::new(data);
    // murmur3_32 returns u32 with seed; Python mmh3.hash returns signed i32
    let hash = murmur3::murmur3_32(&mut reader, 0).unwrap_or(0);
    hash as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_matches_python() {
        // Python: hashlib.md5(b"hello world").hexdigest()
        let result = hex_digest(openssl::hash::MessageDigest::md5(), b"hello world");
        assert_eq!(result, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_sha256_matches_python() {
        // Python: hashlib.sha256(b"hello world").hexdigest()
        let result = hex_digest(openssl::hash::MessageDigest::sha256(), b"hello world");
        assert_eq!(result, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_mmh3_matches_python() {
        // Python: mmh3.hash(b"hello world") -> 1586663183
        assert_eq!(mmh3_32(b"hello world"), 1586663183);
    }

    #[test]
    fn test_mmh3_empty_matches_python() {
        // Python: mmh3.hash(b"") -> 0
        assert_eq!(mmh3_32(b""), 0);
    }

    #[test]
    fn test_response_hash_body_hashes() {
        let hash = ResponseHash::compute(b"test body", &[]);
        assert!(!hash.body_md5.is_empty());
        assert!(!hash.body_sha256.is_empty());
        // Verify body hashes are for "test body"
        assert_eq!(hash.body_md5, hex_digest(openssl::hash::MessageDigest::md5(), b"test body"));
        assert_eq!(hash.body_sha256, hex_digest(openssl::hash::MessageDigest::sha256(), b"test body"));
        assert_eq!(hash.body_mmh3, mmh3_32(b"test body"));
    }

    #[test]
    fn test_response_hash_header_format() {
        // BBOT joins headers as "Name: Value\r\nName: Value"
        let headers = vec![
            ("content-type".to_string(), "text/html".to_string()),
            ("server".to_string(), "nginx".to_string()),
        ];
        let hash = ResponseHash::compute(b"", &headers);

        let expected_raw = "content-type: text/html\r\nserver: nginx";
        assert_eq!(hash.header_md5, hex_digest(openssl::hash::MessageDigest::md5(), expected_raw.as_bytes()));
        assert_eq!(hash.header_sha256, hex_digest(openssl::hash::MessageDigest::sha256(), expected_raw.as_bytes()));
        assert_eq!(hash.header_mmh3, mmh3_32(expected_raw.as_bytes()));
    }
}
