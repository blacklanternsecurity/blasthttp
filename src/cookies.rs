//! Request-scoped cookie handling for redirect chains.
//!
//! [`ChainCookies`] holds what one request's redirect chain picked up:
//! cookies set by one hop are offered to later hops in the same chain, then
//! dropped when the request returns. Nothing survives into the next request,
//! so a result depends only on that request's own inputs.
//!
//! Deliberately not a cookie jar in the sense the word usually carries. There
//! is no session behind it, no storage that outlives a request, and nothing
//! shared between them. Client-wide storage would take away the property that
//! matters here, since concurrent requests sharing it would race to write it,
//! and a batch of 500 URLs would stop being 500 independent results.
//!
//! Within a chain the behavior matches a browser: `Set-Cookie` on a `302`
//! is applied to the hop that follows it. That's how nearly every login
//! flow works: post credentials, get back a session cookie plus a
//! redirect, and the cookie has to be on the next request for it to mean
//! anything. Bot-check pages work the same way. Which cookie goes to which
//! hop follows the RFC 6265 domain, path, and `Secure` rules, so a cookie
//! is never sent to a host it doesn't belong to.
//!
//! The domain rules are the load-bearing ones there, and the shape check
//! alone isn't enough for them: `Domain=com` covers the host that set it, so
//! it passes, and then covers every other `.com` in the chain. A `Domain` is
//! therefore checked against the Public Suffix List, and a cookie may only
//! widen within one registrable domain. See `parse_set_cookie`.
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

/// Ceilings on what one chain will hold.
///
/// A response may legally carry as many `Set-Cookie` headers as it likes, and
/// without a ceiling every hop after it carries all of them: 90 cookies of 2KB
/// in a single redirect is enough to make the next request send a 180KB
/// `Cookie` header, and each further hop can add more. Pointed at hosts we
/// don't trust, which is the normal case, that is a target deciding how much
/// memory we hold and how much traffic we send.
///
/// The numbers come from what real clients and servers already do. RFC 6265
/// 6.1 asks a user agent to support at least 4096 bytes per cookie and at
/// least 50 cookies per domain, which browsers implement as roughly their
/// limits too, so a chain needing more than that is not a login flow. And a
/// `Cookie` header past about 8KB is one the next server rejects anyway
/// (nginx's `large_client_header_buffers` and Apache's `LimitRequestFieldSize`
/// both default near there), so growing past it would only mean sending
/// traffic that cannot be answered.
const MAX_COOKIE_BYTES: usize = 4096;
const MAX_COOKIES: usize = 50;
const MAX_CHAIN_BYTES: usize = 8192;

/// What one cookie costs against `MAX_CHAIN_BYTES`: the `name=value` pair plus
/// the `; ` that joins it to the next one, so the budget bounds the header
/// that actually goes on the wire rather than just the parts of it.
fn entry_size(name: &str, value: &str) -> usize {
    name.len() + value.len() + 3
}

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

/// What [`ChainCookies::store`] decided not to keep. Both kinds are worth
/// logging: a site trying to overwrite a cookie you pinned is something you
/// want to see, and a cap that silently drops cookies reads as full coverage
/// when it isn't.
#[derive(Debug, Default)]
pub struct Rejected {
    /// Names the caller set themselves, so the site doesn't get to touch them.
    pub caller_owned: Vec<String>,
    /// Names dropped because the chain is at one of its ceilings.
    pub over_limit: Vec<String>,
}

impl Rejected {
    fn note(list: &mut Vec<String>, name: &str) {
        if !list.iter().any(|n| n == name) {
            list.push(name.to_string());
        }
    }
}

/// Cookies accumulated over one request's redirect chain.
#[derive(Debug, Default, Clone)]
pub struct ChainCookies {
    cookies: Vec<Cookie>,
    /// Names the caller set in their own `Cookie` header. The chain never
    /// stores or sends a cookie under one of these.
    caller_names: Vec<String>,
}

impl ChainCookies {
    pub fn new() -> Self {
        ChainCookies {
            cookies: Vec::new(),
            caller_names: Vec::new(),
        }
    }

    /// Chain cookies that leave the caller's own alone. `caller_names` are
    /// the names from their `Cookie` header, via [`caller_cookie_names`];
    /// nothing the chain sets under those names is ever stored or sent.
    pub fn with_caller_cookies(caller_names: Vec<String>) -> Self {
        ChainCookies {
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
    /// Anything naming a cookie the caller set is refused outright, as is
    /// anything that would push the chain past its ceilings. Both come back
    /// in the [`Rejected`] report for the caller to log.
    pub fn store(&mut self, headers: &[(String, String)], uri: &http::Uri) -> Rejected {
        let mut rejected = Rejected::default();
        let Some(host) = uri.host() else {
            return rejected;
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
                Rejected::note(&mut rejected.caller_owned, &cookie.name);
                continue;
            }
            // One oversized cookie is refused on its own, before it can eat
            // the whole chain's budget.
            if entry_size(&cookie.name, &cookie.value) > MAX_COOKIE_BYTES {
                Rejected::note(&mut rejected.over_limit, &cookie.name);
                continue;
            }
            // §5.3 step 11: a new cookie replaces one with the same
            // name/domain/path rather than adding a duplicate. Find it now,
            // but leave it in place: whether the replacement is allowed to
            // land depends on the room the old value frees, and if it isn't
            // allowed then dropping the incumbent would mean a refusal costs
            // the caller a cookie they already had.
            let replacing = self.cookies.iter().position(|c| {
                c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path
            });
            if expired {
                if let Some(i) = replacing {
                    self.cookies.remove(i);
                }
                continue;
            }
            let freed = replacing
                .map(|i| entry_size(&self.cookies[i].name, &self.cookies[i].value))
                .unwrap_or(0);
            let held = self.cookies.len() - usize::from(replacing.is_some());
            // Whoever gets there first keeps the room. A chain's own early
            // cookies are the ones a login flow needs, so the sensible thing
            // to drop is whatever a later hop piles on top, not what we
            // already hold.
            if held >= MAX_COOKIES
                || self.bytes() - freed + entry_size(&cookie.name, &cookie.value) > MAX_CHAIN_BYTES
            {
                Rejected::note(&mut rejected.over_limit, &cookie.name);
                continue;
            }
            if let Some(i) = replacing {
                self.cookies.remove(i);
            }
            self.cookies.push(cookie);
        }
        rejected
    }

    /// What the stored cookies currently cost against `MAX_CHAIN_BYTES`.
    fn bytes(&self) -> usize {
        self.cookies
            .iter()
            .map(|c| entry_size(&c.name, &c.value))
            .sum()
    }

    /// The `Cookie` header value to send to `uri`, or `None` when nothing
    /// stored applies to it.
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
///
/// Also unwraps the brackets `Uri::host()` puts around an IPv6 literal. They
/// aren't part of the name, and leaving them on breaks every check downstream
/// that expects one: `[::1]` doesn't parse as an address, so the guard saying
/// an address only matches itself never fires, and the domain rules end up
/// running on a string with a `]` in it.
fn canonical_host(host: &str) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// True when `domain` is a public suffix: a name anyone can register under,
/// like `com`, `co.uk`, `github.io` or `s3.amazonaws.com`. A `Domain`
/// attribute naming one of these is not a boundary a cookie may span, since
/// the hosts beneath it belong to unrelated parties.
///
/// A name whose TLD isn't in the list (`corp`, `localhost`) counts as a
/// suffix, which is the safe direction: an unknown name gets treated as a
/// boundary rather than as somewhere a cookie may widen into.
fn is_public_suffix(domain: &str) -> bool {
    psl::domain_str(domain).is_none()
}

/// The registrable domain, one label below the public suffix: `example.com`
/// for `auth.example.com`, `example.co.uk` for `a.b.example.co.uk`. `None`
/// when the name is a public suffix and has no registrable part.
fn registrable(host: &str) -> Option<&str> {
    psl::domain_str(host)
}

/// RFC 6265 §5.1.3. True when `host` is `domain` or a subdomain of it. An
/// IP literal only ever matches itself, so a `Domain` attribute can never
/// widen a cookie set by an IP address.
///
/// This is only the shape check. Whether the `Domain` is somewhere a cookie
/// is allowed to reach is decided in `parse_set_cookie`, which is where the
/// public suffix rules live: on its own this happily accepts `Domain=com`
/// from any `.com` host.
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

    let (domain, host_only) = match domain {
        // No `Domain` at all: the cookie goes back only to the exact host
        // that set it.
        None => (request_host.to_string(), true),
        Some(d) => {
            // §5.3 step 6: the attribute has to cover the host that sent it.
            if !domain_matches(request_host, &d) {
                return None;
            }
            if request_host.parse::<std::net::IpAddr>().is_ok() {
                // An IP has no domain hierarchy to widen into, so the only
                // `Domain` that got past step 6 is the address itself, and it
                // buys nothing over host-only.
                (request_host.to_string(), true)
            } else if is_public_suffix(&d) {
                // §5.3 step 5. `Domain=com` from `attacker.com` passes step 6
                // and would then be sent to every other `.com` in the chain,
                // which is a redirect walking a cookie onto an unrelated
                // host. Anyone can register under a public suffix, so it can
                // never be a boundary a cookie is allowed to span. The
                // exception the RFC carves out is a host that *is* the
                // suffix, where the attribute says nothing extra and the
                // cookie stays host-only. That's what keeps `Domain=localhost`
                // working, since an unlisted TLD counts as a suffix.
                if d == request_host {
                    (request_host.to_string(), true)
                } else {
                    return None;
                }
            } else if registrable(request_host) != registrable(&d) {
                // Stricter than step 5, and cheap once the list is here. Step
                // 5 alone still lets a host under a suffix reach past its own
                // registrable domain when the wider name isn't itself listed:
                // `attacker.s3.amazonaws.com` setting `Domain=amazonaws.com`
                // would reach `victim.s3.amazonaws.com`, because only
                // `s3.amazonaws.com` is in the list. Requiring both names to
                // land on the same registrable domain closes that and still
                // allows every real widening, `auth.example.com` handing a
                // cookie to `app.example.com` included.
                return None;
            } else {
                (d, false)
            }
        }
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

    // Everything above came off the wire, so none of it is trustworthy as
    // arithmetic input. RFC 6265 5.1.1 says to give up on a time field out of
    // range, which also keeps the multiplications below in bounds.
    if !(0..=23).contains(&h) || !(0..=59).contains(&m) || !(0..=60).contains(&sec) {
        return None;
    }
    // Same section: a year below 1601 isn't a date, so give up rather than
    // guess. There is no ceiling in the spec, but a year large enough to
    // overflow the seconds calculation means the same thing as the largest
    // one that doesn't, namely that this cookie is not expiring, so clamp
    // instead of panicking in a debug build or wrapping to a past date in a
    // release one.
    if year < 1601 {
        return None;
    }
    let year = year.min(9999);

    Some(days_from_civil(year, month, day) * 86400 + h * 3600 + m * 60 + sec)
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
/// `days_from_civil`). Avoids pulling in a date crate for one calculation.
///
/// Callers must bound `y` first: this multiplies out, so an unbounded year
/// straight from a header overflows. `parse_http_date` clamps to the RFC's
/// 1601 floor and a 9999 ceiling.
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

    fn set(chain: &mut ChainCookies, url: &str, values: &[&str]) {
        let headers: Vec<(String, String)> = values
            .iter()
            .map(|v| ("set-cookie".to_string(), v.to_string()))
            .collect();
        chain.store(&headers, &uri(url));
    }

    #[test]
    fn cookie_set_on_redirect_is_sent_to_next_hop() {
        let mut chain = ChainCookies::new();
        set(
            &mut chain,
            "https://example.com/login",
            &["session=abc123; Path=/"],
        );
        assert_eq!(
            chain.header_for(&uri("https://example.com/dashboard")),
            Some("session=abc123".to_string())
        );
    }

    #[test]
    fn host_only_cookie_does_not_reach_subdomains_or_siblings() {
        let mut chain = ChainCookies::new();
        // No Domain attribute -> host-only.
        set(&mut chain, "https://example.com/", &["a=1"]);
        assert!(chain.header_for(&uri("https://www.example.com/")).is_none());
        assert!(chain.header_for(&uri("https://evil.com/")).is_none());
        assert!(chain.header_for(&uri("https://example.com/")).is_some());
    }

    #[test]
    fn domain_attribute_covers_subdomains() {
        let mut chain = ChainCookies::new();
        set(
            &mut chain,
            "https://www.example.com/",
            &["a=1; Domain=example.com"],
        );
        assert!(chain.header_for(&uri("https://example.com/")).is_some());
        assert!(chain.header_for(&uri("https://api.example.com/")).is_some());
        // Suffix match must land on a label boundary.
        assert!(chain.header_for(&uri("https://notexample.com/")).is_none());
    }

    #[test]
    fn domain_not_covering_the_setting_host_is_rejected() {
        let mut chain = ChainCookies::new();
        // A redirect target must not be able to set cookies for elsewhere.
        set(
            &mut chain,
            "https://evil.com/",
            &["a=1; Domain=example.com"],
        );
        assert!(chain.is_empty());
        assert!(chain.header_for(&uri("https://example.com/")).is_none());
    }

    #[test]
    fn domain_of_a_public_suffix_is_refused() {
        // The case that makes this rule necessary: hop 1 on a host the
        // attacker owns sets a cookie scoped to the whole suffix, and without
        // this every later hop under that suffix carries it. Anyone can
        // register under these, so the hosts beneath them are unrelated
        // parties, not one site.
        for (setter, suffix, victim) in [
            ("https://attacker.com/x", "com", "https://victim.com/"),
            ("https://attacker.co.uk/x", "co.uk", "https://victim.co.uk/"),
            (
                "https://attacker.github.io/x",
                "github.io",
                "https://victim.github.io/",
            ),
            (
                "https://attacker.s3.amazonaws.com/x",
                "s3.amazonaws.com",
                "https://victim.s3.amazonaws.com/",
            ),
            // Only `s3.amazonaws.com` is listed, not `amazonaws.com`, so the
            // RFC's own rule would let this one through. Requiring the same
            // registrable domain is what stops it.
            (
                "https://attacker.s3.amazonaws.com/x",
                "amazonaws.com",
                "https://victim.s3.amazonaws.com/",
            ),
        ] {
            let mut chain = ChainCookies::new();
            set(
                &mut chain,
                setter,
                &[&format!("session=forced; Domain={}; Path=/", suffix)],
            );
            assert_eq!(
                chain.header_for(&uri(victim)),
                None,
                "Domain={} reached {}",
                suffix,
                victim
            );
            // Not even kept for the host that set it: a cookie scoped that
            // wide is one the RFC says to ignore outright.
            assert_eq!(chain.header_for(&uri(setter)), None, "Domain={}", suffix);
        }
    }

    #[test]
    fn widening_within_one_registrable_domain_still_works() {
        // The flows this whole feature exists for: an auth host hands a
        // cookie to the app host under the same domain.
        let mut chain = ChainCookies::new();
        set(
            &mut chain,
            "https://auth.example.com/login",
            &["session=abc; Domain=example.com; Path=/"],
        );
        assert_eq!(
            chain
                .header_for(&uri("https://app.example.com/dashboard"))
                .as_deref(),
            Some("session=abc")
        );

        // Same one label deeper, and under a two-label suffix.
        let mut chain = ChainCookies::new();
        set(
            &mut chain,
            "https://a.b.example.co.uk/login",
            &["session=abc; Domain=example.co.uk"],
        );
        assert_eq!(
            chain
                .header_for(&uri("https://www.example.co.uk/"))
                .as_deref(),
            Some("session=abc")
        );

        // An unlisted TLD is treated as a suffix, so `internal.corp` is a
        // registrable domain and a cookie may span it. Local and lab targets
        // keep working.
        let mut chain = ChainCookies::new();
        set(
            &mut chain,
            "https://host.internal.corp/login",
            &["session=abc; Domain=internal.corp"],
        );
        assert_eq!(
            chain
                .header_for(&uri("https://other.internal.corp/"))
                .as_deref(),
            Some("session=abc")
        );
    }

    #[test]
    fn domain_equal_to_the_host_stays_host_only() {
        // RFC 6265 5.3 step 5's carve-out. `localhost` is a suffix as far as
        // the list is concerned, so without this a cookie set on localhost
        // with an explicit Domain would be dropped, and testing against a
        // local target would quietly stop working.
        let mut chain = ChainCookies::new();
        set(
            &mut chain,
            "http://localhost:8080/login",
            &["session=abc; Domain=localhost"],
        );
        assert_eq!(
            chain
                .header_for(&uri("http://localhost:8080/next"))
                .as_deref(),
            Some("session=abc")
        );
        // Host-only, so it doesn't reach a subdomain of it.
        assert_eq!(chain.header_for(&uri("http://sub.localhost/")), None);
    }

    #[test]
    fn ipv6_literal_host_cannot_widen_via_domain() {
        // `Uri::host()` hands back an IPv6 literal in brackets, so the guard
        // that says an address only ever matches itself never fired: the
        // bracketed string doesn't parse as an address, and the domain rules
        // then ran on a name with a `]` in it. `Domain=3.4]` covers
        // `[::ffff:1.2.3.4]` on a dot boundary, and covered every other
        // literal ending the same way.
        let mut chain = ChainCookies::new();
        set(
            &mut chain,
            "http://[::ffff:1.2.3.4]/x",
            &["stolen=attacker_value; Domain=3.4]; Path=/"],
        );
        assert_eq!(
            chain.header_for(&uri("http://[::ffff:9.9.3.4]/admin")),
            None,
            "cookie walked from one IPv6 literal to another"
        );

        // The address still gets its own cookies, host-only.
        let mut chain = ChainCookies::new();
        set(&mut chain, "http://[::1]/x", &["mine=1"]);
        assert_eq!(
            chain.header_for(&uri("http://[::1]/other")).as_deref(),
            Some("mine=1")
        );
        assert_eq!(chain.header_for(&uri("http://[::2]/other")), None);
    }

    #[test]
    fn ip_host_cannot_widen_via_domain() {
        let mut chain = ChainCookies::new();
        set(&mut chain, "http://10.0.0.1/", &["a=1; Domain=0.0.1"]);
        assert!(chain.is_empty());
    }

    #[test]
    fn secure_cookie_is_withheld_over_plaintext() {
        let mut chain = ChainCookies::new();
        set(&mut chain, "https://example.com/", &["s=1; Secure", "p=2"]);
        assert_eq!(
            chain.header_for(&uri("http://example.com/")),
            Some("p=2".to_string())
        );
        assert!(
            chain
                .header_for(&uri("https://example.com/"))
                .unwrap()
                .contains("s=1")
        );
    }

    #[test]
    fn path_scoping() {
        let mut chain = ChainCookies::new();
        set(&mut chain, "https://example.com/", &["a=1; Path=/admin"]);
        assert!(
            chain
                .header_for(&uri("https://example.com/admin"))
                .is_some()
        );
        assert!(
            chain
                .header_for(&uri("https://example.com/admin/users"))
                .is_some()
        );
        // Prefix must break on a boundary, not mid-segment.
        assert!(
            chain
                .header_for(&uri("https://example.com/administrator"))
                .is_none()
        );
        assert!(
            chain
                .header_for(&uri("https://example.com/other"))
                .is_none()
        );
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
        let mut chain = ChainCookies::new();
        set(
            &mut chain,
            "https://example.com/",
            &["broad=1; Path=/", "narrow=2; Path=/admin/panel"],
        );
        assert_eq!(
            chain.header_for(&uri("https://example.com/admin/panel")),
            Some("narrow=2; broad=1".to_string())
        );
    }

    #[test]
    fn resetting_the_same_cookie_replaces_it() {
        let mut chain = ChainCookies::new();
        set(&mut chain, "https://example.com/", &["a=1"]);
        set(&mut chain, "https://example.com/", &["a=2"]);
        assert_eq!(
            chain.header_for(&uri("https://example.com/")),
            Some("a=2".to_string())
        );
    }

    #[test]
    fn expired_cookie_deletes_instead_of_storing() {
        let mut chain = ChainCookies::new();
        set(&mut chain, "https://example.com/", &["a=1"]);
        set(&mut chain, "https://example.com/", &["a=; Max-Age=0"]);
        assert!(chain.header_for(&uri("https://example.com/")).is_none());

        set(&mut chain, "https://example.com/", &["b=1"]);
        set(
            &mut chain,
            "https://example.com/",
            &["b=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"],
        );
        assert!(chain.header_for(&uri("https://example.com/")).is_none());
    }

    #[test]
    fn future_expiry_is_kept() {
        let mut chain = ChainCookies::new();
        set(
            &mut chain,
            "https://example.com/",
            &["a=1; Expires=Tue, 01 Jan 2999 00:00:00 GMT"],
        );
        assert!(chain.header_for(&uri("https://example.com/")).is_some());
    }

    #[test]
    fn malformed_set_cookie_is_ignored() {
        let mut chain = ChainCookies::new();
        set(
            &mut chain,
            "https://example.com/",
            &["novalue", "=noname", ""],
        );
        assert!(chain.is_empty());
    }

    #[test]
    fn host_matching_is_case_and_trailing_dot_insensitive() {
        let mut chain = ChainCookies::new();
        set(&mut chain, "https://Example.COM./", &["a=1"]);
        assert!(chain.header_for(&uri("https://example.com/")).is_some());
    }

    #[test]
    fn empty_value_is_preserved() {
        let mut chain = ChainCookies::new();
        set(&mut chain, "https://example.com/", &["a="]);
        assert_eq!(
            chain.header_for(&uri("https://example.com/")),
            Some("a=".to_string())
        );
    }

    #[test]
    fn caller_cookie_beats_one_the_site_sets() {
        // The whole rule in one case: caller pinned `session`, site tries to
        // reset it mid-chain, and the site loses.
        let mut chain = ChainCookies::with_caller_cookies(vec!["session".to_string()]);
        let refused = chain.store(
            &[(
                "Set-Cookie".to_string(),
                "session=theirs; Path=/".to_string(),
            )],
            &uri("http://example.com/start"),
        );
        assert_eq!(refused.caller_owned, vec!["session".to_string()]);
        // Nothing to add to the caller's header, so the chain has nothing to
        // say for the next hop and their `Cookie` goes out untouched.
        assert_eq!(chain.header_for(&uri("http://example.com/end")), None);
    }

    #[test]
    fn caller_cookie_wins_whatever_scope_the_site_claims() {
        // Domain and Path don't buy the site a way around it, and neither
        // does setting it from a subdomain.
        let mut chain = ChainCookies::with_caller_cookies(vec!["session".to_string()]);
        chain.store(
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
        assert_eq!(
            chain.header_for(&uri("http://app.example.com/admin/x")),
            None
        );
    }

    #[test]
    fn site_cannot_delete_a_caller_cookie() {
        // An expiry is a delete signal, and the caller's cookie isn't the
        // site's to delete.
        let mut chain = ChainCookies::with_caller_cookies(vec!["session".to_string()]);
        let refused = chain.store(
            &[("Set-Cookie".to_string(), "session=; Max-Age=0".to_string())],
            &uri("http://example.com/logout"),
        );
        assert_eq!(refused.caller_owned, vec!["session".to_string()]);
        assert_eq!(chain.header_for(&uri("http://example.com/")), None);
    }

    #[test]
    fn other_names_the_site_sets_still_come_through() {
        // Only the names the caller claimed are off limits.
        let mut chain = ChainCookies::with_caller_cookies(vec!["session".to_string()]);
        chain.store(
            &[
                ("Set-Cookie".to_string(), "session=theirs".to_string()),
                ("Set-Cookie".to_string(), "csrf=xyz".to_string()),
            ],
            &uri("http://example.com/start"),
        );
        assert_eq!(
            chain.header_for(&uri("http://example.com/end")).as_deref(),
            Some("csrf=xyz")
        );
    }

    #[test]
    fn cookie_names_are_case_sensitive() {
        // RFC 6265 4.1.1: `Session` and `session` are different cookies, so
        // pinning one doesn't pin the other.
        let mut chain = ChainCookies::with_caller_cookies(vec!["session".to_string()]);
        chain.store(
            &[("Set-Cookie".to_string(), "Session=theirs".to_string())],
            &uri("http://example.com/start"),
        );
        assert_eq!(
            chain.header_for(&uri("http://example.com/end")).as_deref(),
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
    fn one_oversized_cookie_is_refused() {
        // 4096 bytes is what RFC 6265 6.1 asks a client to support, so
        // anything past it is past what a real site needs.
        let mut chain = ChainCookies::new();
        let big = "A".repeat(MAX_COOKIE_BYTES);
        let rejected = chain.store(
            &[("Set-Cookie".to_string(), format!("big={}", big))],
            &uri("http://example.com/"),
        );
        assert_eq!(rejected.over_limit, vec!["big".to_string()]);
        assert_eq!(chain.header_for(&uri("http://example.com/")), None);

        // Just inside the limit still goes in.
        let mut chain = ChainCookies::new();
        let ok = "A".repeat(MAX_COOKIE_BYTES - entry_size("ok", ""));
        let rejected = chain.store(
            &[("Set-Cookie".to_string(), format!("ok={}", ok))],
            &uri("http://example.com/"),
        );
        assert!(rejected.over_limit.is_empty());
        assert!(chain.header_for(&uri("http://example.com/")).is_some());
    }

    #[test]
    fn storage_stops_at_the_cookie_count() {
        let mut chain = ChainCookies::new();
        let headers: Vec<(String, String)> = (0..MAX_COOKIES + 10)
            .map(|i| ("Set-Cookie".to_string(), format!("c{}=v", i)))
            .collect();
        let rejected = chain.store(&headers, &uri("http://example.com/"));
        assert_eq!(rejected.over_limit.len(), 10);
        let header = chain.header_for(&uri("http://example.com/")).unwrap();
        assert_eq!(header.split("; ").count(), MAX_COOKIES);
        // First come, first served: what the chain set early is what a login
        // flow needs, so a later hop can't push it out.
        assert!(header.contains("c0=v"));
        assert!(!header.contains(&format!("c{}=v", MAX_COOKIES)));
    }

    #[test]
    fn storage_stops_at_the_byte_budget() {
        // 30 cookies of 1KB is under the count limit but way over the byte
        // budget, which is the shape that produced a 180KB `Cookie` header
        // before there were any ceilings.
        let mut chain = ChainCookies::new();
        let value = "A".repeat(1024);
        let headers: Vec<(String, String)> = (0..30)
            .map(|i| ("Set-Cookie".to_string(), format!("c{}={}", i, value)))
            .collect();
        let rejected = chain.store(&headers, &uri("http://example.com/"));
        assert!(!rejected.over_limit.is_empty());
        let header = chain.header_for(&uri("http://example.com/")).unwrap();
        assert!(
            header.len() <= MAX_CHAIN_BYTES,
            "emitted {} bytes, budget is {}",
            header.len(),
            MAX_CHAIN_BYTES
        );
        assert!(header.contains("c0="));
    }

    #[test]
    fn resetting_a_cookie_does_not_leak_budget() {
        // Replacing a value frees what the old one held, so a site that
        // updates the same cookie every hop never fills the budget.
        let mut chain = ChainCookies::new();
        let value = "A".repeat(1000);
        for _ in 0..50 {
            let rejected = chain.store(
                &[("Set-Cookie".to_string(), format!("session={}", value))],
                &uri("http://example.com/"),
            );
            assert!(rejected.over_limit.is_empty());
        }
        let header = chain.header_for(&uri("http://example.com/")).unwrap();
        assert_eq!(header.len(), entry_size("session", &value) - 2);
    }

    #[test]
    fn absurd_expires_values_do_not_panic() {
        // `Expires` is attacker-controlled text off the wire, and the year
        // and time fields were parsed straight into i64 and multiplied out.
        // A year of 3e11 overflows the seconds calculation, which aborts a
        // debug build and wraps in release.
        let mut chain = ChainCookies::new();
        chain.store(
            &[
                (
                    "Set-Cookie".to_string(),
                    "a=1; Expires=Thu, 01 Jan 300000000000 00:00:00 GMT".to_string(),
                ),
                (
                    "Set-Cookie".to_string(),
                    "b=2; Expires=Mon, 01 Jan 2020 9223372036854775807:00:00".to_string(),
                ),
                (
                    "Set-Cookie".to_string(),
                    format!("c=3; Expires=Mon, 01 Jan {} 00:00:00 GMT", i64::MAX),
                ),
                (
                    "Set-Cookie".to_string(),
                    "d=4; Expires=Mon, 01 Jan 1000 00:00:00 GMT".to_string(),
                ),
            ],
            &uri("http://example.com/"),
        );

        // A year past what a date can mean is a promise the cookie outlives
        // the request, so it stays. A time field out of range, or a year
        // below the RFC's 1601 floor, is not a date at all and RFC 6265 5.1.1
        // says to give up on it, which leaves those cookies with the
        // no-expiry default. So all four survive, and none of them take the
        // process down on the way.
        let header = chain.header_for(&uri("http://example.com/")).unwrap();
        for name in ["a=1", "b=2", "c=3", "d=4"] {
            assert!(header.contains(name), "{} missing from {}", name, header);
        }
    }

    #[test]
    fn a_refused_replacement_leaves_the_old_cookie_alone() {
        // The §5.3-step-11 eviction used to run before the budget check, so
        // refusing an oversized replacement still cost you the cookie it was
        // replacing. On a site whose cookies come to about 8KB, re-issuing a
        // bigger session cookie mid-redirect left the rest of the chain with
        // no session at all, which is a silent auth failure in exactly the
        // flow this feature exists for.
        let mut chain = ChainCookies::new();
        set(&mut chain, "http://example.com/", &["session=abc123"]);
        let filler: Vec<String> = (0..9)
            .map(|i| format!("f{}={}", i, "x".repeat(900)))
            .collect();
        set(
            &mut chain,
            "http://example.com/",
            &filler.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert!(
            chain
                .header_for(&uri("http://example.com/"))
                .unwrap()
                .contains("session=abc123")
        );

        let rejected = chain.store(
            &[(
                "Set-Cookie".to_string(),
                format!("session={}", "B".repeat(1500)),
            )],
            &uri("http://example.com/"),
        );

        assert_eq!(rejected.over_limit, vec!["session".to_string()]);
        assert!(
            chain
                .header_for(&uri("http://example.com/"))
                .unwrap()
                .contains("session=abc123"),
            "the incumbent was dropped for a replacement that never landed"
        );
    }

    #[test]
    fn a_replacement_that_fits_reuses_the_old_cookie_s_room() {
        // The other half: a same-name reset has to be measured against the
        // budget with the value it replaces taken out, or a site that
        // re-issues one large cookie every hop fills the chain up.
        let mut chain = ChainCookies::new();
        for _ in 0..20 {
            let rejected = chain.store(
                &[(
                    "Set-Cookie".to_string(),
                    format!("session={}", "B".repeat(4000)),
                )],
                &uri("http://example.com/"),
            );
            assert!(rejected.over_limit.is_empty(), "{:?}", rejected.over_limit);
        }
        let header = chain.header_for(&uri("http://example.com/")).unwrap();
        assert_eq!(header.len(), entry_size("session", &"B".repeat(4000)) - 2);
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
