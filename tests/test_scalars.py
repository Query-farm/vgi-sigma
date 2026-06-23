"""End-to-end tests for the per-row scalar sigma functions.

These spawn ``sigma_worker.py`` as a subprocess via ``vgi.client.Client`` and
call each scalar exactly as DuckDB would after ``ATTACH``. Both the event and
the rule travel in the input batch as ``Param`` columns.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pyarrow as pa
import pytest
from vgi import Arguments
from vgi.client import Client

_WORKER = str(Path(__file__).resolve().parent.parent / "sigma_worker.py")

_RULE = (
    "title: Failed Network Logon\n"
    "logsource: {product: windows, service: security}\n"
    "detection:\n"
    "  selection:\n"
    "    EventID: 4625\n"
    "    LogonType: 3\n"
    "  condition: selection\n"
)


@pytest.fixture(scope="module")
def client() -> Iterator[Client]:
    with Client(f"{sys.executable} {_WORKER}", worker_limit=1) as c:
        yield c


def _match(client: Client, events: list, rules: list) -> list:
    batch = pa.RecordBatch.from_pydict(
        {
            "e": pa.array(events, type=pa.string()),
            "r": pa.array(rules, type=pa.string()),
        }
    )
    results = list(
        client.scalar_function(
            function_name="sigma_match",
            input=iter([batch]),
            arguments=Arguments(positional=[]),
        )
    )
    return results[0]["result"].to_pylist()


def _check(client: Client, rules: list) -> list:
    batch = pa.RecordBatch.from_pydict({"r": pa.array(rules, type=pa.string())})
    results = list(
        client.scalar_function(
            function_name="sigma_check",
            input=iter([batch]),
            arguments=Arguments(positional=[]),
        )
    )
    return results[0]["result"].to_pylist()


class TestSigmaMatch:
    def test_match_and_nonmatch(self, client: Client) -> None:
        out = _match(
            client,
            ['{"EventID": 4625, "LogonType": 3}', '{"EventID": 4624, "LogonType": 3}'],
            [_RULE, _RULE],
        )
        assert out == [True, False]

    def test_null_passthrough(self, client: Client) -> None:
        out = _match(client, [None, '{"EventID": 4625, "LogonType": 3}'], [_RULE, None])
        assert out == [None, None]

    def test_malformed_event_is_false(self, client: Client) -> None:
        out = _match(client, ["not json"], [_RULE])
        assert out == [False]


class TestSigmaCheck:
    def test_valid_and_invalid(self, client: Client) -> None:
        out = _check(client, [_RULE, ": : not valid : :", None])
        assert out == [True, False, None]
