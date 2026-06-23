"""Integration tests for the sigma table functions.

Drives ``sigma_rule_info`` and ``sigma_match_fields`` through the real
bind -> init -> process lifecycle in-process (no worker subprocess).
"""

from __future__ import annotations

import pyarrow as pa

from vgi_sigma.tables import SigmaMatchFieldsFunction, SigmaRuleInfoFunction

from .harness import invoke_table_function

_RULE = (
    "title: Failed Network Logon\n"
    "id: 12345678-1234-1234-1234-123456789012\n"
    "status: test\n"
    "level: high\n"
    "description: Detect failed network logon\n"
    "tags: [attack.credential_access, attack.t1110]\n"
    "logsource: {product: windows, service: security}\n"
    "detection:\n"
    "  selection:\n"
    "    EventID: 4625\n"
    "    LogonType: 3\n"
    "  condition: selection\n"
)


class TestSigmaRuleInfo:
    def test_columns_and_values(self) -> None:
        table = invoke_table_function(SigmaRuleInfoFunction, positional=(pa.scalar(_RULE),))
        assert table.column_names == [
            "title",
            "id",
            "level",
            "status",
            "description",
            "product",
            "service",
            "tags",
        ]
        assert table.num_rows == 1
        row = table.to_pylist()[0]
        assert row["title"] == "Failed Network Logon"
        assert row["id"] == "12345678-1234-1234-1234-123456789012"
        assert row["level"] == "high"
        assert row["status"] == "test"
        assert row["product"] == "windows"
        assert row["service"] == "security"
        assert "attack.t1110" in row["tags"]

    def test_minimal_rule_nullable_columns(self) -> None:
        minimal = "title: T\nlogsource: {category: test}\ndetection:\n  sel: {A: 1}\n  condition: sel\n"
        table = invoke_table_function(SigmaRuleInfoFunction, positional=(pa.scalar(minimal),))
        row = table.to_pylist()[0]
        assert row["title"] == "T"
        assert row["level"] is None
        assert row["tags"] == []


class TestSigmaMatchFields:
    def test_referenced_fields(self) -> None:
        table = invoke_table_function(SigmaMatchFieldsFunction, positional=(pa.scalar(_RULE),))
        assert table.column_names == ["field"]
        fields = sorted(table.column("field").to_pylist())
        assert fields == ["EventID", "LogonType"]
