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
