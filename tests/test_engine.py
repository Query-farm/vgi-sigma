"""Unit tests for the pure Sigma engine (parse, compile, evaluate).

No Arrow / VGI involved -- these exercise ``vgi_sigma.engine`` directly, which is
where all the matching logic lives.
"""

from __future__ import annotations

import pytest

from vgi_sigma import engine

# A canonical Windows failed-network-logon rule used across several tests.
LOGON_RULE = """
title: Failed Network Logon
id: 12345678-1234-1234-1234-123456789012
status: test
level: high
description: Detect failed network logon (EventID 4625, LogonType 3)
tags:
    - attack.credential_access
    - attack.t1110
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType: 3
    condition: selection
"""


def _rule(body: str) -> str:
    """A minimal valid rule (Sigma requires a non-empty logsource)."""
    return "title: T\nlogsource: {category: test}\n" + body


class TestMatchEquality:
    def test_matching_event(self) -> None:
        assert engine.match('{"EventID": 4625, "LogonType": 3}', LOGON_RULE) is True

    def test_wrong_eventid(self) -> None:
        assert engine.match('{"EventID": 4624, "LogonType": 3}', LOGON_RULE) is False

    def test_wrong_logontype(self) -> None:
        assert engine.match('{"EventID": 4625, "LogonType": 2}', LOGON_RULE) is False

    def test_missing_field(self) -> None:
        assert engine.match('{"EventID": 4625}', LOGON_RULE) is False

    def test_number_as_string(self) -> None:
        # JSON often stringifies numbers; equality should still hold.
        assert engine.match('{"EventID": "4625", "LogonType": "3"}', LOGON_RULE) is True

    def test_case_insensitive_string_equality(self) -> None:
        rule = _rule("detection:\n  sel:\n    Image: CMD.EXE\n  condition: sel\n")
        assert engine.match('{"Image": "cmd.exe"}', rule) is True


class TestModifiers:
    def test_contains(self) -> None:
        rule = _rule("detection:\n  sel:\n    CommandLine|contains: whoami\n  condition: sel\n")
        assert engine.match('{"CommandLine": "run whoami now"}', rule) is True
        assert engine.match('{"CommandLine": "no match"}', rule) is False

    def test_startswith(self) -> None:
        rule = _rule("detection:\n  sel:\n    Path|startswith: 'C:\\\\Windows'\n  condition: sel\n")
        assert engine.match('{"Path": "C:\\\\Windows\\\\System32"}', rule) is True
        assert engine.match('{"Path": "D:\\\\Windows"}', rule) is False

    def test_endswith(self) -> None:
        rule = _rule("detection:\n  sel:\n    Image|endswith: '\\\\cmd.exe'\n  condition: sel\n")
        assert engine.match('{"Image": "C:\\\\Windows\\\\cmd.exe"}', rule) is True
        assert engine.match('{"Image": "C:\\\\cmd.exe.bak"}', rule) is False

    def test_regex(self) -> None:
        rule = _rule("detection:\n  sel:\n    Field|re: '^abc[0-9]+$'\n  condition: sel\n")
        assert engine.match('{"Field": "abc123"}', rule) is True
        assert engine.match('{"Field": "xabc123"}', rule) is False

    def test_wildcard_in_plain_value(self) -> None:
        rule = _rule("detection:\n  sel:\n    Image: '*\\\\cmd.exe'\n  condition: sel\n")
        assert engine.match('{"Image": "C:\\\\System32\\\\cmd.exe"}', rule) is True

    def test_all_modifier(self) -> None:
        rule = _rule(
            "detection:\n  sel:\n    CommandLine|contains|all:\n      - foo\n      - bar\n  condition: sel\n"
        )
        assert engine.match('{"CommandLine": "foo and bar"}', rule) is True
        assert engine.match('{"CommandLine": "only foo"}', rule) is False


class TestListAndConditions:
    def test_or_list_value(self) -> None:
        rule = _rule("detection:\n  sel:\n    EventID: [1, 4688]\n  condition: sel\n")
        assert engine.match('{"EventID": 4688}', rule) is True
        assert engine.match('{"EventID": 1}', rule) is True
        assert engine.match('{"EventID": 2}', rule) is False

    def test_one_of_selection(self) -> None:
        rule = _rule(
            "detection:\n"
            "  selection_a: {EventID: 1}\n"
            "  selection_b: {EventID: 2}\n"
            "  condition: 1 of selection_*\n"
        )
        assert engine.match('{"EventID": 2}', rule) is True
        assert engine.match('{"EventID": 3}', rule) is False

    def test_all_of_them(self) -> None:
        rule = _rule("detection:\n  s1: {A: 1}\n  s2: {B: 2}\n  condition: all of them\n")
        assert engine.match('{"A": 1, "B": 2}', rule) is True
        assert engine.match('{"A": 1}', rule) is False

    def test_and_not(self) -> None:
        rule = _rule("detection:\n  sel: {A: 1}\n  filt: {B: 2}\n  condition: sel and not filt\n")
        assert engine.match('{"A": 1}', rule) is True
        assert engine.match('{"A": 1, "B": 2}', rule) is False

    def test_keyword_search(self) -> None:
        rule = _rule("detection:\n  keywords:\n    - mimikatz\n  condition: keywords\n")
        assert engine.match('{"CommandLine": "run mimikatz.exe"}', rule) is True
        assert engine.match('{"CommandLine": "benign tool"}', rule) is False


class TestNestedAndLists:
    def test_dotted_nested_field(self) -> None:
        rule = _rule("detection:\n  sel:\n    process.name: cmd.exe\n  condition: sel\n")
        assert engine.match('{"process": {"name": "cmd.exe"}}', rule) is True
        assert engine.match('{"process": {"name": "ps.exe"}}', rule) is False

    def test_event_value_is_list(self) -> None:
        rule = _rule("detection:\n  sel:\n    Hashes: deadbeef\n  condition: sel\n")
        assert engine.match('{"Hashes": ["cafe", "deadbeef"]}', rule) is True
        assert engine.match('{"Hashes": ["cafe"]}', rule) is False

    def test_field_null(self) -> None:
        rule = _rule("detection:\n  sel:\n    User: null\n  condition: sel\n")
        assert engine.match('{"EventID": 1}', rule) is True  # field absent
        assert engine.match('{"User": null}', rule) is True
        assert engine.match('{"User": "alice"}', rule) is False


class TestCheck:
    def test_valid(self) -> None:
        assert engine.check(LOGON_RULE) is True

    def test_invalid_yaml(self) -> None:
        assert engine.check(": : not valid : :") is False

    def test_not_a_rule(self) -> None:
        assert engine.check("just a string") is False

    def test_missing_logsource(self) -> None:
        assert engine.check("title: T\ndetection:\n  sel: {A: 1}\n  condition: sel\n") is False

    def test_unsupported_modifier_fails_check(self) -> None:
        rule = _rule("detection:\n  sel:\n    ip|cidr: '10.0.0.0/8'\n  condition: sel\n")
        assert engine.check(rule) is False

    def test_null(self) -> None:
        assert engine.check(None) is None


class TestUnsupported:
    def test_match_raises_on_unsupported(self) -> None:
        rule = _rule("detection:\n  sel:\n    ip|cidr: '10.0.0.0/8'\n  condition: sel\n")
        with pytest.raises(engine.UnsupportedRuleError):
            engine.match('{"ip": "10.1.1.1"}', rule)

    def test_match_raises_on_malformed_rule(self) -> None:
        with pytest.raises(engine.RuleParseError):
            engine.match('{"a": 1}', ": : bad : :")


class TestMalformedAndNull:
    def test_null_event(self) -> None:
        assert engine.match(None, LOGON_RULE) is None

    def test_null_rule(self) -> None:
        assert engine.match("{}", None) is None

    def test_malformed_event_json_is_non_match(self) -> None:
        assert engine.match("not json at all", LOGON_RULE) is False

    def test_non_object_event_is_non_match(self) -> None:
        assert engine.match("[1, 2, 3]", LOGON_RULE) is False


class TestRuleInfo:
    def test_fields(self) -> None:
        info = engine.rule_info(LOGON_RULE)
        assert info is not None
        assert info.title == "Failed Network Logon"
        assert info.id == "12345678-1234-1234-1234-123456789012"
        assert info.level == "high"
        assert info.status == "test"
        assert info.product == "windows"
        assert info.service == "security"
        assert "attack.t1110" in info.tags

    def test_null(self) -> None:
        assert engine.rule_info(None) is None

    def test_malformed_raises(self) -> None:
        with pytest.raises(engine.RuleParseError):
            engine.rule_info(": : bad : :")


class TestMatchFields:
    def test_referenced_fields_sorted(self) -> None:
        assert engine.match_fields(LOGON_RULE) == ["EventID", "LogonType"]

    def test_null(self) -> None:
        assert engine.match_fields(None) is None


class TestCaching:
    def test_compile_is_cached(self) -> None:
        engine.compile_rule.cache_clear()
        engine.compile_rule(LOGON_RULE)
        engine.compile_rule(LOGON_RULE)
        info = engine.compile_rule.cache_info()
        assert info.hits >= 1
