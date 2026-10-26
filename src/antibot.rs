//! Working out what a bot-management product did to a request.
//!
//! A scan has to tell three things apart that all arrive looking like a
//! response: the origin answered, a protection product answered instead, or
//! the product answered and handed us a session anyway. Collapsing those is
//! what turns a protected host into an apparently dead one, which is the
//! false negative this exists to prevent.
//!
//! Two rules, both learned by getting them wrong:
//!
//! 1. Never match a vendor's name in the body. `datadome.co`, `imperva.com`
//!    and `kasada.io` all scored as challenges purely from their own marketing
//!    copy. Everything here keys on headers, cookies, status, or a body string
//!    that cannot occur in ordinary prose.
//!
//! 2. A response that merely *references* a vendor's script is not a challenge
//!    page. Every page on a protected site carries the loader; only a page
//!    shaped like an interception is a block.
//!
//! The rules themselves are data, in `antibot_rules.json`: the copy built in
//! is the default, and [`set_rules`] swaps in another at runtime, so a rule
//! can change without a rebuild.

use std::fmt;
use std::sync::{Arc, LazyLock, RwLock};

use serde::Deserialize;

/// Which product answered, named by the rule that matched. Deliberately
/// conservative: guessing a vendor wrong is worse than reporting unknown.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vendor(String);

impl Vendor {
    pub fn new(name: impl Into<String>) -> Self {
        Vendor(name.into())
    }

    /// A refusal no rule could put a name to.
    pub fn unknown() -> Self {
        Vendor::new("unknown")
    }

    pub fn is_unknown(&self) -> bool {
        self.0 == "unknown"
    }
}

impl fmt::Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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

    /// Is there positive evidence that a protection product intervened?
    ///
    /// The distinction between this and "we did not get through" matters, and
    /// getting it wrong costs real requests. Most 403s are ordinary
    /// authorization failures: an endpoint needing a token, a path that is not
    /// public, a method that is not allowed. Those classify as
    /// `Blocked(Unknown)` because they are refusals with no product signature,
    /// and retrying them with different TLS settings is pure waste against a
    /// server that will say 403 however it is asked.
    ///
    /// So a named vendor is the bar. It means something recognisable answered
    /// instead of the origin, which is the only case where trying a different
    /// profile is worth a second request.
    ///
    /// The cost of that conservatism is missing a product we cannot
    /// fingerprint. The cost of the alternative is doubling the request count
    /// of every scan that touches a 403, which is most of them.
    pub fn indicates_protection(&self) -> bool {
        self.vendor().is_some_and(|v| !v.is_unknown())
    }

    pub fn vendor(&self) -> Option<&Vendor> {
        match self {
            Outcome::Present(v) | Outcome::Challenge(v) | Outcome::Blocked(v) => Some(v),
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
        let mut end = self.body.len().min(WINDOW);
        // The cut can land in the middle of a multi-byte character, and
        // slicing a str there panics rather than erring. A body truncated by
        // max_body_size puts arbitrary bytes at the cap, so this is reachable
        // from the wire. Walk back to the nearest boundary.
        while end > 0 && !self.body.is_char_boundary(end) {
            end -= 1;
        }
        self.body[..end].contains(needle)
    }
}

/// The rules a classification runs, as loaded from `antibot_rules.json`.
///
/// Order matters, and the first rule to match decides: a challenge outranks a
/// mere sighting of the vendor, and a block outranks both, because a host that
/// challenges us has still told us more than one that refuses outright.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// Statuses a protection product uses to refuse. 429 belongs because a rate
    /// limit and a bot block are the same outcome for a scan, whoever sent it.
    refusal_statuses: Vec<u16>,
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    vendor: String,
    outcome: RuleOutcome,
    /// What the outcome becomes when the status is a refusal.
    on_refusal: Option<RuleOutcome>,
    when: Condition,
    /// Why the rule is shaped the way it is. Not used, but worth keeping.
    #[allow(dead_code)]
    why: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuleOutcome {
    Present,
    Challenge,
    Blocked,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Condition {
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
    Status(Statuses),
    HeaderPresent(String),
    /// Case-insensitive, in both the name and the value.
    HeaderContains {
        name: String,
        value: String,
    },
    CookieSet(String),
    CookiePrefix(String),
    BodyContains(String),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Statuses {
    Codes(Vec<u16>),
    Named(NamedStatuses),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NamedStatuses {
    Refusal,
}

impl Rules {
    pub fn from_json(json: &str) -> Result<Rules, serde_json::Error> {
        let rules: Rules = serde_json::from_str(json)?;
        if rules.rules.iter().any(|r| r.vendor.is_empty()) {
            return Err(serde::de::Error::custom("every rule needs a vendor"));
        }
        Ok(rules)
    }

    /// Classify one response.
    pub fn classify(&self, facts: &ResponseFacts) -> Outcome {
        let refusal = self.is_refusal(facts.status);
        if let Some(rule) = self.rules.iter().find(|r| self.matches(&r.when, facts)) {
            let vendor = Vendor::new(&rule.vendor);
            return match (refusal, rule.on_refusal) {
                (true, Some(outcome)) => outcome,
                _ => rule.outcome,
            }
            .with(vendor);
        }
        // Nothing identifiable
        if (200..400).contains(&facts.status) {
            Outcome::Ok
        } else if refusal {
            Outcome::Blocked(Vendor::unknown())
        } else {
            Outcome::Error
        }
    }

    fn is_refusal(&self, status: u16) -> bool {
        self.refusal_statuses.contains(&status)
    }

    fn matches(&self, condition: &Condition, facts: &ResponseFacts) -> bool {
        match condition {
            Condition::All(conditions) => conditions.iter().all(|c| self.matches(c, facts)),
            Condition::Any(conditions) => conditions.iter().any(|c| self.matches(c, facts)),
            Condition::Not(condition) => !self.matches(condition, facts),
            Condition::Status(Statuses::Codes(codes)) => codes.contains(&facts.status),
            Condition::Status(Statuses::Named(NamedStatuses::Refusal)) => {
                self.is_refusal(facts.status)
            }
            Condition::HeaderPresent(name) => facts.has_header(name),
            Condition::HeaderContains { name, value } => {
                facts.header_matches(name, &value.to_ascii_lowercase())
            }
            Condition::CookieSet(name) => facts.sets_cookie(name),
            Condition::CookiePrefix(prefix) => facts.sets_cookie_prefixed(prefix),
            Condition::BodyContains(needle) => facts.body_contains(needle),
        }
    }
}

impl RuleOutcome {
    fn with(self, vendor: Vendor) -> Outcome {
        match self {
            RuleOutcome::Present => Outcome::Present(vendor),
            RuleOutcome::Challenge => Outcome::Challenge(vendor),
            RuleOutcome::Blocked => Outcome::Blocked(vendor),
        }
    }
}

impl Default for Rules {
    /// The rules built in from `antibot_rules.json`.
    fn default() -> Self {
        Rules::from_json(include_str!("../antibot_rules.json"))
            .expect("the built-in antibot_rules.json is valid")
    }
}

static RULES: LazyLock<RwLock<Arc<Rules>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Rules::default())));

/// Replace the rules every later classification runs, in this process.
pub fn set_rules(rules: Rules) {
    *RULES.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(rules);
}

/// Classify one response with the current rules.
pub fn classify(facts: &ResponseFacts) -> Outcome {
    let rules = RULES.read().unwrap_or_else(|e| e.into_inner()).clone();
    rules.classify(facts)
}
