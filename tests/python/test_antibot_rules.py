"""Replacing the anti-bot rules from Python, with a JSON file shaped like the built-in one."""

import json

import pytest

import blasthttp

CHALLENGE_PAGE = b"<html>example-challenge</html>"


def protection(body):
    return blasthttp.Response("https://example.test/", 200, headers=[], body=body).protection


@pytest.fixture
def restore_rules():
    yield
    blasthttp.set_antibot_rules()


def test_a_rules_file_replaces_the_rules(tmp_path, restore_rules):
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            {
                "refusal_statuses": [403],
                "rules": [
                    {"vendor": "examplewaf", "outcome": "challenge", "when": {"body_contains": "example-challenge"}}
                ],
            }
        )
    )
    assert protection(CHALLENGE_PAGE) == ("ok", "-")
    blasthttp.set_antibot_rules(str(rules))
    assert protection(CHALLENGE_PAGE) == ("challenge", "examplewaf")
    blasthttp.set_antibot_rules()
    assert protection(CHALLENGE_PAGE) == ("ok", "-")


def test_a_bad_rules_file_raises_and_keeps_the_rules(tmp_path, restore_rules):
    rules = tmp_path / "rules.json"
    rules.write_text('{"refusal_statuses": [], "rules": [{"vendor": "x", "outcome": "maybe", "when": {}}]}')
    with pytest.raises(ValueError, match="rules.json"):
        blasthttp.set_antibot_rules(str(rules))
    with pytest.raises(ValueError, match="missing.json"):
        blasthttp.set_antibot_rules(str(tmp_path / "missing.json"))
    assert protection(b'<html><script src="/_Incapsula_Resource?SWJIYLWA=abc"></script></html>') == (
        "challenge",
        "imperva",
    )
