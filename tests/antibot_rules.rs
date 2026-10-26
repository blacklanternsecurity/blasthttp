// Loading anti-bot rules from JSON: what a rules file can say, and how a bad
// one fails.

use blasthttp::antibot::{Outcome, ResponseFacts, Rules, Vendor};

fn facts<'a>(status: u16, headers: &'a [(String, String)], body: &'a str) -> ResponseFacts<'a> {
    ResponseFacts {
        status,
        headers,
        body,
    }
}

fn header(name: &str, value: &str) -> Vec<(String, String)> {
    vec![(name.to_string(), value.to_string())]
}

const CUSTOM: &str = r#"{
    "refusal_statuses": [403],
    "rules": [
        {
            "vendor": "examplewaf",
            "outcome": "challenge",
            "when": {"all": [{"status": "refusal"}, {"body_contains": "example-challenge"}]}
        },
        {
            "vendor": "examplewaf",
            "outcome": "present",
            "on_refusal": "blocked",
            "when": {"cookie_prefix": "exwaf_"}
        },
        {
            "vendor": "otherwaf",
            "outcome": "blocked",
            "when": {"all": [
                {"header_contains": {"name": "X-Edge", "value": "OtherWAF"}},
                {"not": {"status": [200]}}
            ]}
        }
    ]
}"#;

#[test]
fn test_a_rules_file_can_name_a_new_vendor() {
    let rules = Rules::from_json(CUSTOM).unwrap();
    let none = vec![];
    assert_eq!(
        rules.classify(&facts(403, &none, "<html>example-challenge</html>")),
        Outcome::Challenge(Vendor::new("examplewaf"))
    );
    // the same body on a status the file doesn't call a refusal
    assert_eq!(
        rules.classify(&facts(503, &none, "<html>example-challenge</html>")),
        Outcome::Error
    );
}

#[test]
fn test_on_refusal_changes_the_outcome_on_a_refusal_only() {
    let rules = Rules::from_json(CUSTOM).unwrap();
    let cookie = header("set-cookie", "exwaf_session=abc; Path=/");
    assert_eq!(
        rules.classify(&facts(200, &cookie, "welcome")),
        Outcome::Present(Vendor::new("examplewaf"))
    );
    assert_eq!(
        rules.classify(&facts(403, &cookie, "go away")),
        Outcome::Blocked(Vendor::new("examplewaf"))
    );
}

#[test]
fn test_header_contains_ignores_case() {
    let rules = Rules::from_json(CUSTOM).unwrap();
    let edge = header("x-edge", "otherwaf-7");
    assert_eq!(
        rules.classify(&facts(404, &edge, "")),
        Outcome::Blocked(Vendor::new("otherwaf"))
    );
    assert_eq!(rules.classify(&facts(200, &edge, "")), Outcome::Ok);
}

#[test]
fn test_a_rules_file_replaces_the_built_in_rules() {
    let rules = Rules::from_json(CUSTOM).unwrap();
    let mitigated = header("cf-mitigated", "challenge");
    assert_eq!(
        Rules::default().classify(&facts(403, &mitigated, "")),
        Outcome::Challenge(Vendor::new("cloudflare"))
    );
    assert_eq!(
        rules.classify(&facts(403, &mitigated, "")),
        Outcome::Blocked(Vendor::unknown())
    );
}

#[test]
fn test_a_bad_rules_file_is_refused() {
    for bad in [
        // not JSON
        "{",
        // a condition that doesn't exist
        r#"{"refusal_statuses": [], "rules": [{"vendor": "x", "outcome": "challenge", "when": {"body_matches": "x"}}]}"#,
        // an outcome that doesn't exist
        r#"{"refusal_statuses": [], "rules": [{"vendor": "x", "outcome": "maybe", "when": {"body_contains": "x"}}]}"#,
        // a misspelled field
        r#"{"refusal_statuses": [], "rules": [{"vendor": "x", "outcome": "challenge", "wen": {"body_contains": "x"}}]}"#,
        // no vendor
        r#"{"refusal_statuses": [], "rules": [{"vendor": "", "outcome": "challenge", "when": {"body_contains": "x"}}]}"#,
        // no rules at all
        r#"{"refusal_statuses": []}"#,
    ] {
        assert!(Rules::from_json(bad).is_err(), "accepted: {bad}");
    }
}
