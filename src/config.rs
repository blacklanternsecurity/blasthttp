use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestConfig {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<Vec<(String, String)>>,
    pub body: Option<Vec<u8>>,
    pub timeout_seconds: Option<u64>,
    pub max_body_size: Option<usize>,
    pub follow_redirects: Option<bool>,
    pub max_redirects: Option<u32>,
    /// Apply cookies a redirect hop sets to the hops that follow it, within
    /// this one request (default: true). What the chain collects lives for
    /// that request only, so nothing carries into the next one and results
    /// stay reproducible.
    /// Set to `false` to send only the caller's own headers on every hop.
    ///
    /// A cookie set in `headers` is never affected by this. Whatever the
    /// caller put in a `Cookie` header is what every hop sends, and a
    /// `Set-Cookie` naming one of those cookies is ignored, so the chain can
    /// neither overwrite it nor delete it.
    pub redirect_cookies: Option<bool>,
    pub verify_certs: Option<bool>,
    pub proxy: Option<String>,
    /// Hosts that bypass `proxy` and connect directly (NO_PROXY equivalent).
    /// Entries may be exact hostnames, domain suffixes (`*.corp` / `.corp` /
    /// `corp`), single IPs, CIDR ranges (`10.0.0.0/8`), or `*` for all.
    #[serde(default)]
    pub no_proxy: Vec<String>,
    pub cipher_string: Option<String>,
    pub min_tls_version: Option<String>,
    pub max_tls_version: Option<String>,
    /// Number of retries on retryable errors (default: 1)
    pub retries: Option<u32>,
    /// Minimum backoff between retries in milliseconds (default: 1000)
    pub retry_wait_min_ms: Option<u64>,
    /// Maximum backoff between retries in milliseconds (default: 30000)
    pub retry_wait_max_ms: Option<u64>,
    /// No-op — paths are already sent raw. Kept for API compat with curl --path-as-is.
    pub raw_path: Option<bool>,
    /// Override the HTTP request-line target (like curl --request-target).
    /// Only applies to HTTP/1.1. Bypasses the cached connection pool.
    pub request_target: Option<String>,
    /// Connect TCP to this IP instead of resolving the hostname via DNS
    /// (like curl --resolve). SNI is still set to the original hostname.
    pub resolve_ip: Option<String>,
    /// ALPN protocol list offered during the TLS handshake. When None,
    /// raw connections offer only `http/1.1`. Set to e.g.
    /// `vec!["h2".into()]` to negotiate HTTP/2, or `vec!["h2".into(),
    /// "http/1.1".into()]` to let the server choose. Only meaningful
    /// for HTTPS targets; ignored for plain HTTP.
    pub alpn_protocols: Option<Vec<String>>,
    #[serde(default)]
    pub verbosity: u8,
}

impl RequestConfig {
    pub fn new(url: String) -> Self {
        RequestConfig {
            url,
            method: None,
            headers: None,
            body: None,
            timeout_seconds: None,
            max_body_size: None,
            follow_redirects: None,
            max_redirects: None,
            redirect_cookies: None,
            verify_certs: None,
            proxy: None,
            no_proxy: Vec::new(),
            cipher_string: None,
            min_tls_version: None,
            max_tls_version: None,
            retries: None,
            retry_wait_min_ms: None,
            retry_wait_max_ms: None,
            raw_path: None,
            request_target: None,
            resolve_ip: None,
            alpn_protocols: None,
            verbosity: 0,
        }
    }

    pub fn method(&self) -> &str {
        self.method.as_deref().unwrap_or("GET")
    }

    pub fn timeout(&self) -> u64 {
        self.timeout_seconds.unwrap_or(10)
    }

    pub fn max_body(&self) -> usize {
        self.max_body_size.unwrap_or(10 * 1024 * 1024)
    }

    pub fn should_follow_redirects(&self) -> bool {
        self.follow_redirects.unwrap_or(false)
    }

    pub fn redirect_limit(&self) -> u32 {
        self.max_redirects.unwrap_or(10)
    }

    /// Whether cookies set mid-chain are replayed on later hops. On by
    /// default: it's what a browser does, and it's what lets a login or
    /// bot-check page (the kind that sets a cookie and redirects you back
    /// to where you started) actually resolve instead of looping.
    ///
    /// Cookies the caller set in `headers` are sent either way, and win over
    /// anything the chain sets under the same name.
    pub fn should_forward_redirect_cookies(&self) -> bool {
        self.redirect_cookies.unwrap_or(true)
    }

    pub fn should_verify_certs(&self) -> bool {
        self.verify_certs.unwrap_or(false)
    }

    /// The proxy URL to use for a request to `target_host`, or `None` when no
    /// proxy is configured or the host matches a `no_proxy` entry.
    pub fn effective_proxy(&self, target_host: &str) -> Option<&str> {
        let proxy = self.proxy.as_deref()?;
        if host_bypasses_proxy(target_host, &self.no_proxy) {
            None
        } else {
            Some(proxy)
        }
    }

    /// `no_proxy` only has an effect alongside a `proxy` — it lists hosts that
    /// bypass that proxy. Setting it without a proxy is silently a no-op and
    /// almost always a mistake, so reject it up front. Returns the error
    /// message (caller wraps it in its error type).
    pub fn validate_proxy(&self) -> Result<(), String> {
        let proxy_set = self.proxy.as_deref().is_some_and(|p| !p.trim().is_empty());
        if !self.no_proxy.is_empty() && !proxy_set {
            return Err(
                "no_proxy is set but no proxy is configured; no_proxy only has an effect \
                 when a proxy is also set"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn max_retries(&self) -> u32 {
        self.retries.unwrap_or(1)
    }

    pub fn retry_wait_min(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.retry_wait_min_ms.unwrap_or(1000))
    }

    pub fn retry_wait_max(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.retry_wait_max_ms.unwrap_or(30000))
    }
}

use std::net::IpAddr;

/// Returns true if `host` matches any `no_proxy` pattern, meaning a request to
/// it should bypass the configured proxy. Matching follows the conventional
/// NO_PROXY rules:
///
/// - `*` matches every host.
/// - A CIDR (`10.0.0.0/8`, `fd00::/8`) matches when `host` is an IP inside it.
/// - A bare IP matches that exact address.
/// - Anything else is treated as a domain: it matches the domain itself and any
///   subdomain, case-insensitively. Leading `*.` or `.` are accepted and
///   ignored (`*.corp`, `.corp`, and `corp` are equivalent).
pub(crate) fn host_bypasses_proxy(host: &str, patterns: &[String]) -> bool {
    if host.is_empty() {
        return false;
    }
    // Strip brackets from IPv6 literals so "[::1]" parses as an address.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let host_ip = host.parse::<IpAddr>().ok();
    let host = host.trim_end_matches('.');

    for pattern in patterns {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }
        if pattern == "*" {
            return true;
        }

        if let Some((net, prefix)) = pattern.split_once('/') {
            // CIDR: only meaningful when the target is an IP.
            if let (Some(ip), Ok(net_ip), Ok(prefix_len)) = (
                host_ip,
                net.trim().parse::<IpAddr>(),
                prefix.trim().parse::<u8>(),
            ) && ip_in_cidr(ip, net_ip, prefix_len)
            {
                return true;
            }
            continue;
        }

        if let Ok(pattern_ip) = pattern.parse::<IpAddr>() {
            if Some(pattern_ip) == host_ip {
                return true;
            }
            continue;
        }

        // Hostname / domain-suffix match. An IP target never matches a name.
        if host_ip.is_some() {
            continue;
        }
        let suffix = pattern.trim_start_matches('*').trim_matches('.');
        if !suffix.is_empty() && host_matches_suffix(host, suffix) {
            return true;
        }
    }
    false
}

/// Case-insensitive check that `host` equals `suffix` or is a subdomain of it
/// (i.e. `host` ends in `.<suffix>`). Operates on bytes to avoid allocating.
fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    let (host, suffix) = (host.as_bytes(), suffix.as_bytes());
    if host.len() == suffix.len() {
        return host.eq_ignore_ascii_case(suffix);
    }
    match host.len().checked_sub(suffix.len()) {
        Some(start) if start >= 1 && host[start - 1] == b'.' => {
            host[start..].eq_ignore_ascii_case(suffix)
        }
        _ => false,
    }
}

/// True if `ip` falls within the `net`/`prefix_len` CIDR block. Mismatched
/// address families (v4 vs v6) never match.
fn ip_in_cidr(ip: IpAddr, net: IpAddr, prefix_len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix_len);
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exact_hostname() {
        assert!(host_bypasses_proxy("localhost", &pats(&["localhost"])));
        assert!(host_bypasses_proxy(
            "elastic.corp",
            &pats(&["elastic.corp"])
        ));
        assert!(!host_bypasses_proxy(
            "example.com",
            &pats(&["elastic.corp"])
        ));
    }

    #[test]
    fn case_insensitive_and_trailing_dot() {
        assert!(host_bypasses_proxy("LocalHost.", &pats(&["localhost"])));
        assert!(host_bypasses_proxy(
            "API.Internal.Corp",
            &pats(&["*.internal.corp"])
        ));
    }

    #[test]
    fn domain_suffix_forms_are_equivalent() {
        for p in ["*.internal.corp", ".internal.corp", "internal.corp"] {
            assert!(
                host_bypasses_proxy("api.internal.corp", &pats(&[p])),
                "subdomain should match {p}"
            );
            assert!(
                host_bypasses_proxy("internal.corp", &pats(&[p])),
                "apex should match {p}"
            );
        }
        // A suffix must align on a label boundary.
        assert!(!host_bypasses_proxy(
            "notinternal.corp",
            &pats(&["*.internal.corp"])
        ));
        assert!(!host_bypasses_proxy(
            "internal.corp.evil.com",
            &pats(&["internal.corp"])
        ));
    }

    #[test]
    fn bare_ip() {
        assert!(host_bypasses_proxy("127.0.0.1", &pats(&["127.0.0.1"])));
        assert!(!host_bypasses_proxy("127.0.0.2", &pats(&["127.0.0.1"])));
        assert!(host_bypasses_proxy("::1", &pats(&["::1"])));
        assert!(host_bypasses_proxy("[::1]", &pats(&["::1"])));
    }

    #[test]
    fn cidr_v4() {
        let p = pats(&["10.0.0.0/8"]);
        assert!(host_bypasses_proxy("10.1.2.3", &p));
        assert!(host_bypasses_proxy("10.255.255.255", &p));
        assert!(!host_bypasses_proxy("11.0.0.1", &p));
        // A hostname is never inside a CIDR.
        assert!(!host_bypasses_proxy("ten.example.com", &p));
    }

    #[test]
    fn cidr_v6_and_zero_prefix() {
        assert!(host_bypasses_proxy("fd00::1", &pats(&["fd00::/8"])));
        assert!(!host_bypasses_proxy("fe00::1", &pats(&["fd00::/8"])));
        assert!(host_bypasses_proxy("8.8.8.8", &pats(&["0.0.0.0/0"])));
    }

    #[test]
    fn family_mismatch_never_matches() {
        assert!(!host_bypasses_proxy("10.0.0.1", &pats(&["fd00::/8"])));
        assert!(!host_bypasses_proxy("fd00::1", &pats(&["10.0.0.0/8"])));
    }

    #[test]
    fn wildcard_and_empty() {
        assert!(host_bypasses_proxy("anything.com", &pats(&["*"])));
        assert!(!host_bypasses_proxy("anything.com", &pats(&[])));
        assert!(!host_bypasses_proxy("", &pats(&["*"])));
        assert!(!host_bypasses_proxy("host", &pats(&["", "  "])));
    }

    #[test]
    fn effective_proxy_respects_exclusions() {
        let mut cfg = RequestConfig::new("http://x/".into());
        cfg.proxy = Some("http://proxy:8080".into());
        cfg.no_proxy = pats(&["127.0.0.1", "*.internal.corp"]);
        assert_eq!(
            cfg.effective_proxy("example.com"),
            Some("http://proxy:8080")
        );
        assert_eq!(cfg.effective_proxy("127.0.0.1"), None);
        assert_eq!(cfg.effective_proxy("api.internal.corp"), None);
        // No proxy configured -> always None regardless of no_proxy.
        cfg.proxy = None;
        assert_eq!(cfg.effective_proxy("example.com"), None);
    }

    #[test]
    fn validate_proxy_rejects_no_proxy_without_proxy() {
        let mut cfg = RequestConfig::new("http://x/".into());

        // Neither set, or only proxy set -> fine.
        assert!(cfg.validate_proxy().is_ok());
        cfg.proxy = Some("http://proxy:8080".into());
        assert!(cfg.validate_proxy().is_ok());

        // no_proxy alongside a proxy -> fine.
        cfg.no_proxy = pats(&["127.0.0.1"]);
        assert!(cfg.validate_proxy().is_ok());

        // no_proxy without a proxy -> error.
        cfg.proxy = None;
        assert!(cfg.validate_proxy().is_err());
        // An empty/whitespace proxy counts as unset.
        cfg.proxy = Some("   ".into());
        assert!(cfg.validate_proxy().is_err());
    }
}
