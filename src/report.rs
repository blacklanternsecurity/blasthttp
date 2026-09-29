//! What was tried, and what it means.
//!
//! A request that walks the profile ladder makes several attempts, and the
//! caller sees only the last one. That is fine when it worked and useless when
//! it did not: "403" says nothing about whether a different approach exists,
//! whether one was already tried, or whether anything would have helped.
//!
//! The consumer this is for is BBOT, which has to tell four outcomes apart
//! that all look like "no page":
//!
//!   - the host is dead
//!   - the host needs legacy TLS we declined to offer
//!   - a product blocked us, and here is which
//!   - a product served a JavaScript challenge, so no HTTP client will ever
//!     get through and the URL should go to a real browser
//!
//! Only the last of those justifies launching a browser, and it must be a
//! field rather than something inferred by grepping our response body for
//! `cf-mitigated`.

use serde::{Deserialize, Serialize};

use crate::antibot::{Outcome, Vendor};

/// What one rung of the ladder produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttemptOutcome {
    /// Got a response the classifier was happy with.
    Reached { status: u16 },
    /// A clean handshake, then a refusal.
    Refused {
        status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        vendor: Option<String>,
    },
    /// A challenge: answering it needs JavaScript.
    Challenged {
        status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        vendor: Option<String>,
    },
    /// Never got as far as a response.
    HandshakeFailed { reason: String },
}

/// One rung: which profile, and what happened under it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub profile: String,
    pub outcome: AttemptOutcome,
}

impl Attempt {
    pub fn new(profile: &str, outcome: AttemptOutcome) -> Self {
        Attempt {
            profile: profile.to_string(),
            outcome,
        }
    }

    /// Build from a classifier verdict.
    pub fn from_outcome(profile: &str, status: u16, outcome: &Outcome) -> Self {
        let vendor = outcome
            .vendor()
            .filter(|v| !matches!(v, Vendor::Unknown))
            .map(|v| v.to_string());
        let o = match outcome {
            Outcome::Ok | Outcome::Present(_) => AttemptOutcome::Reached { status },
            Outcome::Challenge(_) => AttemptOutcome::Challenged { status, vendor },
            Outcome::Blocked(_) | Outcome::Error => AttemptOutcome::Refused { status, vendor },
        };
        Attempt::new(profile, o)
    }
}

/// What the whole request amounts to, once every rung has been tried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Conclusion {
    /// Got the page.
    Reached,
    /// A product refused us and nothing we can change is likely to help.
    Blocked {
        #[serde(skip_serializing_if = "Option::is_none")]
        vendor: Option<String>,
    },
    /// A JavaScript challenge. **The signal to hand this URL to a real
    /// browser.** No HTTP client passes this tier, curl_cffi included, and
    /// retrying with different connection settings will not change it.
    NeedsBrowser {
        #[serde(skip_serializing_if = "Option::is_none")]
        vendor: Option<String>,
    },
    /// The peer could not negotiate with us and we had nothing wider to offer.
    /// Distinct from `Unreachable`: the host is alive and talking, it just
    /// wants cryptography we declined or cannot do.
    NeedsLegacyTls { reason: String },
    /// Never got a response at all.
    Unreachable { reason: String },
}

impl Conclusion {
    /// Should the caller hand this to a browser?
    ///
    /// The single question BBOT needs answered, exposed as a predicate so it
    /// does not have to match on the variant.
    pub fn needs_browser(&self) -> bool {
        matches!(self, Conclusion::NeedsBrowser { .. })
    }

    /// Work out the conclusion from the last outcome and what was tried.
    pub fn from_attempts(last: &Outcome, attempts: &[Attempt]) -> Self {
        let vendor = last
            .vendor()
            .filter(|v| !matches!(v, Vendor::Unknown))
            .map(|v| v.to_string());
        match last {
            Outcome::Ok | Outcome::Present(_) => Conclusion::Reached,
            Outcome::Challenge(_) => Conclusion::NeedsBrowser { vendor },
            Outcome::Blocked(_) => Conclusion::Blocked { vendor },
            // A classifier error with attempts behind it means something went
            // wrong that was not a refusal.
            Outcome::Error => Conclusion::Unreachable {
                reason: attempts
                    .last()
                    .map(|a| format!("{:?}", a.outcome))
                    .unwrap_or_else(|| "no response".to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_challenge_asks_for_a_browser_and_a_block_does_not() {
        // The distinction the whole escalation path rests on. A block might
        // yield to different settings; a challenge needs JavaScript and never
        // will, so only one of these justifies starting a browser.
        let challenge = Conclusion::from_attempts(&Outcome::Challenge(Vendor::Cloudflare), &[]);
        assert!(challenge.needs_browser());
        assert_eq!(
            challenge,
            Conclusion::NeedsBrowser {
                vendor: Some("cloudflare".to_string())
            }
        );

        let blocked = Conclusion::from_attempts(&Outcome::Blocked(Vendor::Akamai), &[]);
        assert!(!blocked.needs_browser());
    }

    #[test]
    fn test_an_unnamed_vendor_is_left_unnamed() {
        // Reporting "unknown" as though it were a product would invite a
        // consumer to branch on it. An absent vendor is the honest answer.
        let blocked = Conclusion::from_attempts(&Outcome::Blocked(Vendor::Unknown), &[]);
        assert_eq!(blocked, Conclusion::Blocked { vendor: None });
    }

    #[test]
    fn test_reaching_it_is_not_an_escalation() {
        for outcome in [Outcome::Ok, Outcome::Present(Vendor::Akamai)] {
            let c = Conclusion::from_attempts(&outcome, &[]);
            assert_eq!(c, Conclusion::Reached);
            assert!(!c.needs_browser());
        }
    }

    #[test]
    fn test_attempts_record_the_profile_that_produced_them() {
        // The log is only useful if it says which rung did what.
        let a = Attempt::from_outcome("modern", 403, &Outcome::Challenge(Vendor::PerimeterX));
        assert_eq!(a.profile, "modern");
        assert_eq!(
            a.outcome,
            AttemptOutcome::Challenged {
                status: 403,
                vendor: Some("perimeterx".to_string()),
            }
        );
    }
}
