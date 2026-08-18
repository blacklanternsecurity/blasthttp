//! Request-scoped cookie handling for redirect chains.
//!
//! A [`CookieJar`] lives for exactly one request: cookies set by one hop
//! are offered to later hops in the same redirect chain, then dropped when
//! the request returns. Nothing survives into the next request, so a
//! result depends only on that request's own inputs. A client-wide jar
//! would destroy that, since concurrent requests sharing one would race
//! to write it.
//!
//! Within a chain the behavior matches a browser: `Set-Cookie` on a `302`
//! is applied to the hop that follows it. That's how nearly every login
//! flow works: post credentials, get back a session cookie plus a
//! redirect, and the cookie has to be on the next request for it to mean
//! anything. Bot-check pages work the same way. Which cookie goes to which
//! hop follows the RFC 6265 domain, path, and `Secure` rules, so a cookie
//! is never sent to a host it doesn't belong to.
//!
//! One rule overrides all of that: **a cookie the caller set themselves is
//! what gets sent, always.** If a request carries `Cookie: session=mine`,
//! every hop of that chain sends `session=mine`, whatever the site says.
//! A `Set-Cookie` for a name the caller pinned is not stored, so it can
//! neither replace their value nor delete it, and the two never go out
//! together as a duplicate pair. Sites reset cookies mid-redirect all the
//! time and duplicate names are read inconsistently (some servers take the
//! first, some the last), so the only answer that stays predictable is that
//! what the caller wrote is what lands on the wire.

use std::time::{SystemTime, UNIX_EPOCH};

/// One stored cookie, normalized per RFC 6265 §5.3.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cookie {
    name: String,
    value: String,
    /// Canonicalized (lowercase, no leading dot) domain this cookie is
    /// scoped to.
    domain: String,
    /// True when the response carried no `Domain` attribute, meaning the
    /// cookie goes back only to the exact host that set it, never to a
    /// subdomain.
    host_only: bool,
    path: String,
    secure: bool,
}

/// Cookies accumulated over one request's redirect chain.
#[derive(Debug, Default, Clone)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
    /// Names the caller set in their own `Cookie` header. The chain never
    /// stores or sends a cookie under one of these.
    caller_names: Vec<String>,
}

impl CookieJar {
    pub fn new() -> Self {
        CookieJar {
            cookies: Vec::new(),
            caller_names: Vec::new(),
        }
    }

    /// A jar that leaves the caller's own cookies alone. `caller_names` are
    /// the names from their `Cookie` header, via [`caller_cookie_names`];
    /// nothing the chain sets under those names is ever stored or sent.
    pub fn with_caller_cookies(caller_names: Vec<String>) -> Self {
        CookieJar {
            cookies: Vec::new(),
            caller_names,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Take every `Set-Cookie` out of a response that came back from
    /// `uri`. Cookies whose `Domain` doesn't cover `uri`'s host are
    /// dropped, and an expired cookie (`Max-Age=0`, or `Expires` in the
    /// past, the usual "log out" / "clear this" signal) deletes any
    /// matching cookie already held instead of being stored.
    ///
    /// Anything naming a cookie the caller set is refused outright, and its
    /// name comes back in the return value. Worth logging rather than
    /// swallowing: a site trying to overwrite a cookie you pinned is
    /// something you want to know it did.
    pub fn store(&mut self, headers: &[(String, String)], uri: &http::Uri) -> Vec<String> {
        let mut refused: Vec<String> = Vec::new();
        let Some(host) = uri.host() else {
            return refused;
        };
        let host = canonical_host(host);
        let request_path = uri.path();

        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let Some((cookie, expired)) = parse_set_cookie(value, &host, request_path) else {
                continue;
            };
            // The caller's own cookie wins, always. Refusing to store it is
            // what makes that hold everywhere at once: the value can't be
            // replaced, can't be deleted by an expiry, and can't go out
            // beside the caller's as a duplicate name. Cookie names are
            // case-sensitive (RFC 6265 4.1.1), so compare them exactly.
            if self.caller_names.contains(&cookie.name) {
                if !refused.contains(&cookie.name) {
                    refused.push(cookie.name);
                }
                continue;
            }
            // §5.3 step 11: a new cookie replaces one with the same
            // name/domain/path rather than adding a duplicate.
            self.cookies.retain(|c| {
                !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path)
            });
            if !expired {
                self.cookies.push(cookie);
            }
        }
        refused
    }

    /// The `Cookie` header value to send to `uri`, or `None` when nothing
    /// in the jar applies to it.
    pub fn header_for(&self, uri: &http::Uri) -> Option<String> {
        let host = canonical_host(uri.host()?);
        let path = uri.path();
        let secure_transport = uri.scheme_str() == Some("https");

        let mut matched: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| {
                if c.secure && !secure_transport {
                    return false;
                }
                if c.host_only {
                    if host != c.domain {
                        return false;
                    }
                } else if !domain_matches(&host, &c.domain) {
                    return false;
                }
                path_matches(path, &c.path)
            })
            .collect();

        if matched.is_empty() {
            return None;
        }

        // §5.4: longer paths first. `sort_by_key` is stable, so cookies
        // with equal path length keep the order they were set in, which is the
        // spec's creation-time tiebreak.
        matched.sort_by_key(|c| std::cmp::Reverse(c.path.len()));

        Some(
            matched
                .iter()
                .map(|c| format!("{}={}", c.name, c.value))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

/// The cookie names a caller set in their own request headers.
///
/// These are off limits to the redirect chain: whatever the caller wrote is
/// what goes on the wire, on every hop. Every `Cookie` header they supplied
/// counts, since the server sees all of them. A pair with no `=` isn't a
/// cookie and is skipped.
pub fn caller_cookie_names(headers: &[(String, String)]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for pair in value.split(';') {
            let Some((n, _)) = pair.split_once('=') else {
                continue;
            };
            let n = n.trim();
            if !n.is_empty() && !names.iter().any(|existing| existing.as_str() == n) {
                names.push(n.to_string());
            }
        }
    }
    names
}

/// Lowercase a host and strip a single trailing dot so `Example.COM.` and
/// `example.com` compare equal.
fn canonical_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// RFC 6265 §5.1.3. True when `host` is `domain` or a subdomain of it. An
/// IP literal only ever matches itself, so a `Domain` attribute can never
/// widen a cookie set by an IP address.
fn domain_matches(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// RFC 6265 §5.1.4. `cookie_path` covers `request_path` when it is equal,
/// or is a prefix ending at a `/` boundary.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path.as_bytes()[cookie_path.len()] == b'/'
}

/// RFC 6265 §5.1.4 default-path: everything up to the last `/` of the
/// request path, or `/` when there isn't one to cut at.
fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}

/// Parse one `Set-Cookie` value in the context of the request it answered.
///
/// Returns the normalized cookie plus whether it is already expired (so the
/// caller deletes rather than stores it), or `None` when the cookie is
/// malformed or its `Domain` doesn't cover `request_host` (§5.3 step 6),
/// which is what stops a redirect target from setting cookies for
/// unrelated hosts.
fn parse_set_cookie(value: &str, request_host: &str, request_path: &str) -> Option<(Cookie, bool)> {
    let mut parts = value.split(';');
    let pair = parts.next()?.trim();
    let (name, val) = pair.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }

    let mut domain: Option<String> = None;
    let mut path: Option<String> = None;
    let mut secure = false;
    let mut max_age: Option<i64> = None;
    let mut expires: Option<i64> = None;

    for attr in parts {
        let attr = attr.trim();
        let (key, aval) = match attr.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (attr, ""),
        };
        if key.eq_ignore_ascii_case("domain") {
            let d = canonical_host(aval.trim_start_matches('.'));
            if !d.is_empty() {
                domain = Some(d);
            }
        } else if key.eq_ignore_ascii_case("path") {
            if aval.starts_with('/') {
                path = Some(aval.to_string());
            }
        } else if key.eq_ignore_ascii_case("secure") {
            secure = true;
        } else if key.eq_ignore_ascii_case("max-age") {
            max_age = aval.parse::<i64>().ok();
        } else if key.eq_ignore_ascii_case("expires") {
            expires = parse_http_date(aval);
        }
    }

    // §5.3 step 6: reject outright if the Domain attribute doesn't cover
    // the host that sent it.
    let (domain, host_only) = match domain {
        Some(d) => {
            if !domain_matches(request_host, &d) {
                return None;
            }
            (d, false)
        }
        None => (request_host.to_string(), true),
    };

    // Max-Age wins over Expires (§5.3 step 3). A non-positive Max-Age, or
    // an Expires in the past, means "delete this".
    let expired = match max_age {
        Some(secs) => secs <= 0,
        None => match expires {
            Some(when) => when <= now_unix(),
            None => false,
        },
    };

    Some((
        Cookie {
            name: name.to_string(),
            value: val.trim().to_string(),
            domain,
            host_only,
            path: path.unwrap_or_else(|| default_path(request_path)),
            secure,
        },
        expired,
    ))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Tolerant HTTP-date parser covering the formats cookies actually use:
/// IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), RFC 850 with a 2-digit
/// year (`Sunday, 06-Nov-94 08:49:37 GMT`), and asctime. Rather than match
/// formats it tokenizes and picks out day / month / year / time, which is
/// how real clients cope with the variety servers emit. Returns seconds
/// since the Unix epoch.
fn parse_http_date(s: &str) -> Option<i64> {
    let normalized: String = s
        .chars()
        .map(|c| if c == '-' || c == ',' { ' ' } else { c })
        .collect();

    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];

    let mut day: Option<i64> = None;
    let mut month: Option<i64> = None;
    let mut year: Option<i64> = None;
    let mut time: Option<(i64, i64, i64)> = None;

    for token in normalized.split_whitespace() {
        if token.contains(':') && time.is_none() {
            let mut it = token.split(':');
            let h = it.next()?.parse::<i64>().ok()?;
            let m = it.next()?.parse::<i64>().ok()?;
            let sec = it.next().and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
            time = Some((h, m, sec));
            continue;
        }
        if month.is_none() && token.len() >= 3 {
            let prefix = token[..3].to_ascii_lowercase();
            if let Some(i) = MONTHS.iter().position(|m| *m == prefix) {
                month = Some(i as i64 + 1);
                continue;
            }
        }
        if let Ok(n) = token.parse::<i64>() {
            // One or two digits is a day-of-month if we still need one; anything
            // else (or a second number) is the year.
            if day.is_none() && token.len() <= 2 && (1..=31).contains(&n) {
                day = Some(n);
            } else if year.is_none() {
                year = Some(if token.len() <= 2 {
                    if n < 70 { 2000 + n } else { 1900 + n }
                } else {
                    n
                });
            }
        }
    }

    let (day, month, year) = (day?, month?, year?);
    let (h, m, sec) = time.unwrap_or((0, 0, 0));
    Some(days_from_civil(year, month, day) * 86400 + h * 3600 + m * 60 + sec)
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
/// `days_from_civil`). Avoids pulling in a date crate for one calculation.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> http::Uri {
        s.parse().unwrap()
    }

    fn set(jar: &mut CookieJar, url: &str, values: &[&str]) {
        let headers: Vec<(String, String)> = values
            .iter()
            .map(|v| ("set-cookie".to_string(), v.to_string()))
            .collect();
        jar.store(&headers, &uri(url));
    }

    #[test]
    fn cookie_set_on_redirect_is_sent_to_next_hop() {
        let mut jar = CookieJar::new();
        set(
            &mut jar,
            "https://example.com/login",
            &["session=abc123; Path=/"],
        );
        assert_eq!(
            jar.header_for(&uri("https://example.com/dashboard")),
            Some("session=abc123".to_string())
        );
    }

    #[test]
    fn host_only_cookie_does_not_reach_subdomains_or_siblings() {
        let mut jar = CookieJar::new();
        // No Domain attribute -> host-only.
        set(&mut jar, "https://example.com/", &["a=1"]);
        assert!(jar.header_for(&uri("https://www.example.com/")).is_none());
        assert!(jar.header_for(&uri("https://evil.com/")).is_none());
        assert!(jar.header_for(&uri("https://example.com/")).is_some());
    }

    #[test]
    fn domain_attribute_covers_subdomains() {
        let mut jar = CookieJar::new();
        set(
            &mut jar,
            "https://www.example.com/",
            &["a=1; Domain=example.com"],
        );
        assert!(jar.header_for(&uri("https://example.com/")).is_some());
        assert!(jar.header_for(&uri("https://api.example.com/")).is_some());
        // Suffix match must land on a label boundary.
        assert!(jar.header_for(&uri("https://notexample.com/")).is_none());
    }

    #[test]
    fn domain_not_covering_the_setting_host_is_rejected() {
        let mut jar = CookieJar::new();
        // A redirect target must not be able to set cookies for elsewhere.
        set(&mut jar, "https://evil.com/", &["a=1; Domain=example.com"]);
        assert!(jar.is_empty());
        assert!(jar.header_for(&uri("https://example.com/")).is_none());
    }

    #[test]
    fn ip_host_cannot_widen_via_domain() {
        let mut jar = CookieJar::new();
        set(&mut jar, "http://10.0.0.1/", &["a=1; Domain=0.0.1"]);
        assert!(jar.is_empty());
    }

    #[test]
    fn secure_cookie_is_withheld_over_plaintext() {
        let mut jar = CookieJar::new();
        set(&mut jar, "https://example.com/", &["s=1; Secure", "p=2"]);
        assert_eq!(
            jar.header_for(&uri("http://example.com/")),
            Some("p=2".to_string())
        );
        assert!(
            jar.header_for(&uri("https://example.com/"))
                .unwrap()
                .contains("s=1")
        );
    }

    #[test]
    fn path_scoping() {
        let mut jar = CookieJar::new();
        set(&mut jar, "https://example.com/", &["a=1; Path=/admin"]);
        assert!(jar.header_for(&uri("https://example.com/admin")).is_some());
        assert!(
            jar.header_for(&uri("https://example.com/admin/users"))
                .is_some()
        );
        // Prefix must break on a boundary, not mid-segment.
        assert!(
            jar.header_for(&uri("https://example.com/administrator"))
                .is_none()
        );
        assert!(jar.header_for(&uri("https://example.com/other")).is_none());
    }

    #[test]
    fn default_path_is_the_requests_directory() {
        assert_eq!(default_path("/a/b/c"), "/a/b");
        assert_eq!(default_path("/a"), "/");
        assert_eq!(default_path("/"), "/");
        assert_eq!(default_path(""), "/");
    }

    #[test]
    fn longer_paths_are_sent_first() {
        let mut jar = CookieJar::new();
        set(
            &mut jar,
            "https://example.com/",
            &["broad=1; Path=/", "narrow=2; Path=/admin/panel"],
        );
        assert_eq!(
            jar.header_for(&uri("https://example.com/admin/panel")),
            Some("narrow=2; broad=1".to_string())
        );
    }

    #[test]
    fn resetting_the_same_cookie_replaces_it() {
        let mut jar = CookieJar::new();
        set(&mut jar, "https://example.com/", &["a=1"]);
        set(&mut jar, "https://example.com/", &["a=2"]);
        assert_eq!(
            jar.header_for(&uri("https://example.com/")),
            Some("a=2".to_string())
        );
    }

    #[test]
    fn expired_cookie_deletes_instead_of_storing() {
        let mut jar = CookieJar::new();
        set(&mut jar, "https://example.com/", &["a=1"]);
        set(&mut jar, "https://example.com/", &["a=; Max-Age=0"]);
        assert!(jar.header_for(&uri("https://example.com/")).is_none());

        set(&mut jar, "https://example.com/", &["b=1"]);
        set(
            &mut jar,
            "https://example.com/",
            &["b=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"],
        );
        assert!(jar.header_for(&uri("https://example.com/")).is_none());
    }

    #[test]
    fn future_expiry_is_kept() {
        let mut jar = CookieJar::new();
        set(
            &mut jar,
            "https://example.com/",
            &["a=1; Expires=Tue, 01 Jan 2999 00:00:00 GMT"],
        );
        assert!(jar.header_for(&uri("https://example.com/")).is_some());
    }

    #[test]
    fn malformed_set_cookie_is_ignored() {
        let mut jar = CookieJar::new();
        set(
            &mut jar,
            "https://example.com/",
            &["novalue", "=noname", ""],
        );
        assert!(jar.is_empty());
    }

    #[test]
    fn host_matching_is_case_and_trailing_dot_insensitive() {
        let mut jar = CookieJar::new();
        set(&mut jar, "https://Example.COM./", &["a=1"]);
        assert!(jar.header_for(&uri("https://example.com/")).is_some());
    }

    #[test]
    fn empty_value_is_preserved() {
        let mut jar = CookieJar::new();
        set(&mut jar, "https://example.com/", &["a="]);
        assert_eq!(
            jar.header_for(&uri("https://example.com/")),
            Some("a=".to_string())
        );
    }

    #[test]
    fn caller_cookie_beats_one_the_site_sets() {
        // The whole rule in one case: caller pinned `session`, site tries to
        // reset it mid-chain, and the site loses.
        let mut jar = CookieJar::with_caller_cookies(vec!["session".to_string()]);
        let refused = jar.store(
            &[(
                "Set-Cookie".to_string(),
                "session=theirs; Path=/".to_string(),
            )],
            &uri("http://example.com/start"),
        );
        assert_eq!(refused, vec!["session".to_string()]);
        // Nothing to add to the caller's header, so the jar has nothing to
        // say for the next hop and their `Cookie` goes out untouched.
        assert_eq!(jar.header_for(&uri("http://example.com/end")), None);
    }

    #[test]
    fn caller_cookie_wins_whatever_scope_the_site_claims() {
        // Domain and Path don't buy the site a way around it, and neither
        // does setting it from a subdomain.
        let mut jar = CookieJar::with_caller_cookies(vec!["session".to_string()]);
        jar.store(
            &[
                (
                    "Set-Cookie".to_string(),
                    "session=wide; Domain=example.com; Path=/".to_string(),
                ),
                (
                    "Set-Cookie".to_string(),
                    "session=deep; Path=/admin".to_string(),
                ),
            ],
            &uri("http://app.example.com/admin/x"),
        );
        assert_eq!(jar.header_for(&uri("http://app.example.com/admin/x")), None);
    }

    #[test]
    fn site_cannot_delete_a_caller_cookie() {
        // An expiry is a delete signal, and the caller's cookie isn't the
        // site's to delete.
        let mut jar = CookieJar::with_caller_cookies(vec!["session".to_string()]);
        let refused = jar.store(
            &[("Set-Cookie".to_string(), "session=; Max-Age=0".to_string())],
            &uri("http://example.com/logout"),
        );
        assert_eq!(refused, vec!["session".to_string()]);
        assert_eq!(jar.header_for(&uri("http://example.com/")), None);
    }

    #[test]
    fn other_names_the_site_sets_still_come_through() {
        // Only the names the caller claimed are off limits.
        let mut jar = CookieJar::with_caller_cookies(vec!["session".to_string()]);
        jar.store(
            &[
                ("Set-Cookie".to_string(), "session=theirs".to_string()),
                ("Set-Cookie".to_string(), "csrf=xyz".to_string()),
            ],
            &uri("http://example.com/start"),
        );
        assert_eq!(
            jar.header_for(&uri("http://example.com/end")).as_deref(),
            Some("csrf=xyz")
        );
    }

    #[test]
    fn cookie_names_are_case_sensitive() {
        // RFC 6265 4.1.1: `Session` and `session` are different cookies, so
        // pinning one doesn't pin the other.
        let mut jar = CookieJar::with_caller_cookies(vec!["session".to_string()]);
        jar.store(
            &[("Set-Cookie".to_string(), "Session=theirs".to_string())],
            &uri("http://example.com/start"),
        );
        assert_eq!(
            jar.header_for(&uri("http://example.com/end")).as_deref(),
            Some("Session=theirs")
        );
    }

    #[test]
    fn caller_cookie_names_reads_every_cookie_header() {
        let headers = vec![
            ("Cookie".to_string(), "a=1; b=2".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
            // A second `Cookie` header counts too: the server sees both.
            ("cookie".to_string(), " c=3 ;  a=9 ".to_string()),
        ];
        assert_eq!(
            caller_cookie_names(&headers),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn caller_cookie_names_ignores_what_is_not_a_cookie() {
        // No `=` is not a name/value pair, and an empty name is not a name.
        let headers = vec![("Cookie".to_string(), "novalue; =orphan; real=1".to_string())];
        assert_eq!(caller_cookie_names(&headers), vec!["real".to_string()]);
        assert!(caller_cookie_names(&[]).is_empty());
    }

    #[test]
    fn http_date_formats() {
        // IMF-fixdate.
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784111777)
        );
        // RFC 850, two-digit year.
        assert_eq!(
            parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(784111777)
        );
        // asctime.
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), Some(784111777));
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_http_date("garbage"), None);
    }
}
