// `set_rules` swaps the rules every later classification in the process
// runs. Its own test binary, since the rules are process-wide.

use blasthttp::antibot::{Outcome, ResponseFacts, Rules, Vendor, classify, set_rules};

#[test]
fn test_set_rules_replaces_the_rules_classify_runs() {
    let none = vec![];
    let page = ResponseFacts {
        status: 200,
        headers: &none,
        body: "<html>example-challenge</html>",
    };
    assert_eq!(classify(&page), Outcome::Ok);

    set_rules(
        Rules::from_json(
            r#"{"refusal_statuses": [403], "rules": [
                {"vendor": "examplewaf", "outcome": "challenge", "when": {"body_contains": "example-challenge"}}
            ]}"#,
        )
        .unwrap(),
    );
    assert_eq!(
        classify(&page),
        Outcome::Challenge(Vendor::new("examplewaf"))
    );

    set_rules(Rules::default());
    assert_eq!(classify(&page), Outcome::Ok);
}
