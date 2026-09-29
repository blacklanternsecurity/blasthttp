// Classifying what a bot-management product did to a request.
//
// A scan needs to tell three things apart that all look like "a response":
// the origin answered, a protection product answered instead, or the product
// answered *and* handed us a session. Without that, an operator sees a wall of
// 403s and cannot tell a blocked host from a dead one, which is the false
// negative this whole effort exists to fix.
//
// Two rules learned the hard way, both from a first pass that got them wrong:
//
// 1. Never match a vendor's name in the body. `datadome.co`, `imperva.com` and
//    `kasada.io` all scored as challenges purely from their own marketing
//    copy. Everything here keys on headers, cookies, status, or a body string
//    that cannot occur in ordinary prose.
//
// 2. Always classify a known-good reference client in the same pass. A block
//    and a site that simply changed look identical from one sample.

#![allow(dead_code)]

use std::fmt;

/// Which product answered. Not exhaustive, and deliberately conservative:
/// guessing a vendor wrong is worse than reporting `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Cloudflare,
    Akamai,
    DataDome,
    PerimeterX,
    Imperva,
    F5,
    Kasada,
    Unknown,
}

impl fmt::Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Vendor::Cloudflare => "cloudflare",
            Vendor::Akamai => "akamai",
            Vendor::DataDome => "datadome",
            Vendor::PerimeterX => "perimeterx",
            Vendor::Imperva => "imperva",
            Vendor::F5 => "f5",
            Vendor::Kasada => "kasada",
            Vendor::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Ordinary response, no protection product detected.
    Ok,
    /// A product is in front of this host and let us through, usually having
    /// set a session cookie. The most useful signal there is: we passed
    /// something that was actively looking.
    Present(Vendor),
    /// An interactive challenge. Out of reach for any HTTP client, since
    /// answering means executing the page's JavaScript.
    Challenge(Vendor),
    /// A hard refusal, no challenge offered.
    Blocked(Vendor),
    /// Never got a usable response.
    Error,
}

impl Outcome {
    /// Did we get real content? The bar the benchmark scores against.
    pub fn got_through(&self) -> bool {
        matches!(self, Outcome::Ok | Outcome::Present(_))
    }

    pub fn vendor(&self) -> Option<Vendor> {
        match self {
            Outcome::Present(v) | Outcome::Challenge(v) | Outcome::Blocked(v) => Some(*v),
            _ => None,
        }
    }
}

/// Everything a classification looks at. Headers and cookies are expected
/// lowercase-insensitive; `headers` holds `(name, value)` pairs as received,
/// duplicates and all.
pub struct ResponseFacts<'a> {
    pub status: u16,
    pub headers: &'a [(String, String)],
    pub body: &'a str,
}

impl ResponseFacts<'_> {
    fn header_matches(&self, name: &str, needle: &str) -> bool {
        self.headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case(name) && v.to_ascii_lowercase().contains(needle))
    }

    fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(name))
    }

    /// Cookie names set by this response. Only the name is examined; values
    /// are session data and carry nothing we want to match on.
    fn set_cookie_names(&self) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .filter_map(|(_, v)| v.split('=').next())
            .map(|n| n.trim().to_ascii_lowercase())
            .collect()
    }

    fn sets_cookie(&self, name: &str) -> bool {
        let want = name.to_ascii_lowercase();
        self.set_cookie_names().contains(&want)
    }

    fn sets_cookie_prefixed(&self, prefix: &str) -> bool {
        let want = prefix.to_ascii_lowercase();
        self.set_cookie_names().iter().any(|n| n.starts_with(&want))
    }

    fn body_contains(&self, needle: &str) -> bool {
        // Bodies can be large; a challenge marker is always near the top.
        const WINDOW: usize = 64 * 1024;
        let end = self.body.len().min(WINDOW);
        self.body[..end].contains(needle)
    }
}

/// Classify one response.
///
/// Order matters: a challenge outranks a mere sighting of the vendor, and a
/// block outranks both, because a host that challenges us has still told us
/// more than one that refuses outright.
pub fn classify(facts: &ResponseFacts) -> Outcome {
    // ── Cloudflare ────────────────────────────────────────────────
    // `cf-mitigated: challenge` is the unambiguous one and the only header
    // Cloudflare sets specifically to say it intervened.
    if facts.header_matches("cf-mitigated", "challenge") {
        return Outcome::Challenge(Vendor::Cloudflare);
    }
    if facts.body_contains("/cdn-cgi/challenge-platform/")
        || facts.body_contains("window._cf_chl_opt")
    {
        return Outcome::Challenge(Vendor::Cloudflare);
    }

    // ── Akamai ────────────────────────────────────────────────────
    // The edge error page, which is fussier to spot than it looks.
    //
    // It HTML-entity-encodes its own punctuation, so the body carries
    // `errors&#46;edgesuite&#46;net` and a search for `errors.edgesuite.net`
    // never fires. Matching the bare label `edgesuite` survives that, since
    // only the dots and slashes get encoded.
    //
    // `server: AkamaiGHost` is also not reliably present: www.akamai.com's own
    // 403 sends no `server` header at all and identifies itself through
    // `akamai-grn`, `x-akam-sw-version` and an `ak_p` server-timing entry
    // instead. So the server header is one signal among several rather than a
    // requirement. `Reference #` on its own stays insufficient, because plenty
    // of unrelated error pages carry one.
    if facts.body_contains("edgesuite")
        || (is_akamai_edge(facts) && facts.body_contains("Access Denied"))
    {
        return Outcome::Blocked(Vendor::Akamai);
    }
    // sec-cpt is an adaptive challenge that fires after _abck already passed,
    // and it answers 428 rather than 403. Its own outcome, not a block.
    if facts.status == 428 && (facts.sets_cookie("sec_cpt") || facts.body_contains("sec-cpt")) {
        return Outcome::Challenge(Vendor::Akamai);
    }

    // ── DataDome ──────────────────────────────────────────────────
    if facts.body_contains("geo.captcha-delivery.com") {
        return Outcome::Challenge(Vendor::DataDome);
    }

    // ── PerimeterX / HUMAN ────────────────────────────────────────
    if facts.body_contains("/px/captcha") || facts.body_contains("px-captcha") {
        return Outcome::Challenge(Vendor::PerimeterX);
    }

    // ── Imperva / Incapsula ───────────────────────────────────────
    if facts.body_contains("_Incapsula_Resource") {
        return Outcome::Challenge(Vendor::Imperva);
    }

    // ── Kasada ────────────────────────────────────────────────────
    // Kasada answers 429 rather than 403 for a refusal.
    if facts.has_header("x-kpsdk-ct") || facts.body_contains("KPSDK") {
        return if facts.status == 429 {
            Outcome::Blocked(Vendor::Kasada)
        } else {
            Outcome::Present(Vendor::Kasada)
        };
    }

    // ── Product present, and we got through ───────────────────────
    // Reached only when nothing above fired, so these are sightings on a
    // response that actually carried content.
    let present = if facts.sets_cookie("__cf_bm") || facts.sets_cookie("cf_clearance") {
        Some(Vendor::Cloudflare)
    } else if facts.sets_cookie("_abck")
        || facts.sets_cookie("ak_bmsc")
        || facts.sets_cookie("bm_sz")
    {
        Some(Vendor::Akamai)
    } else if facts.sets_cookie("datadome") {
        Some(Vendor::DataDome)
    } else if facts.sets_cookie_prefixed("_px") {
        Some(Vendor::PerimeterX)
    } else if facts.sets_cookie_prefixed("visid_incap_") || facts.sets_cookie_prefixed("incap_ses_")
    {
        Some(Vendor::Imperva)
    } else if facts.header_matches("server", "volt-adc") {
        Some(Vendor::F5)
    } else {
        None
    };

    if let Some(vendor) = present {
        // A product that set its cookie while refusing us is still a block.
        return if is_refusal(facts.status) {
            Outcome::Blocked(vendor)
        } else {
            Outcome::Present(vendor)
        };
    }

    // ── Nothing identifiable ──────────────────────────────────────
    if (200..400).contains(&facts.status) {
        Outcome::Ok
    } else if is_refusal(facts.status) {
        Outcome::Blocked(Vendor::Unknown)
    } else {
        Outcome::Error
    }
}

/// Statuses a protection product uses to refuse. 429 is in here because a rate
/// limit and a bot block are the same outcome for a scan, whoever sent it.
fn is_refusal(status: u16) -> bool {
    matches!(status, 401 | 403 | 405 | 406 | 429 | 503)
}

/// Is this response coming off Akamai's edge at all?
///
/// Any one of these is enough. They are the headers the edge attaches to its
/// own responses regardless of whether it is serving content or refusing.
fn is_akamai_edge(facts: &ResponseFacts) -> bool {
    facts.header_matches("server", "akamaighost")
        || facts.has_header("akamai-grn")
        || facts.has_header("x-akam-sw-version")
        || facts.has_header("x-akamai-transformed")
        || facts.header_matches("server-timing", "ak_p")
}
