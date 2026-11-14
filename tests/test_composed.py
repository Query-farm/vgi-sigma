"""Placement checks for the composed example queries in ``vgi_sigma.composed``.

Each composed example must appear in the schema-level ``vgi.example_queries``
list and within the first five examples of the object that drives the query
(the vgi-lint agent simulator only shows agents the first five per object and
never the schema-level list). Execution is covered by ``test/sql/composed.test``.
"""

from __future__ import annotations

import json

import pytest

from vgi_sigma import composed, worker
from vgi_sigma.scalars import SigmaCheckFunction, SigmaMatchFunction
from vgi_sigma.tables import SigmaMatchFieldsFunction, SigmaRuleInfoFunction


def _schema_tags() -> dict[str, str]:
    return worker._SCHEMA_TAGS


@pytest.mark.parametrize("entry", composed.COMPOSED_EXAMPLE_QUERIES, ids=lambda e: e["description"][:40])
def test_in_schema_example_queries(entry: dict[str, str]) -> None:
    assert entry in json.loads(_schema_tags()["vgi.example_queries"])


@pytest.mark.parametrize(
    ("fn", "sql"),
    [
        (SigmaMatchFunction, composed.RULE_LIBRARY_HUNT_SQL),
        (SigmaRuleInfoFunction, composed.ALERT_ENRICHMENT_SQL),
        (SigmaMatchFieldsFunction, composed.MISSING_FIELDS_SQL),
    ],
)
def test_on_driving_function_first_five(fn: type, sql: str) -> None:
    meta = fn.Meta  # type: ignore[attr-defined]
    assert sql in [ex.sql for ex in meta.examples[:5]]
    assert sql in [q["sql"] for q in json.loads(meta.tags["vgi.example_queries"])[:5]]


def test_on_supported_modifiers_view_first_five() -> None:
    queries = json.loads(worker._SUPPORTED_MODIFIERS_VIEW.tags["vgi.example_queries"])
    assert composed.UNSUPPORTED_MODIFIERS_SQL in [q["sql"] for q in queries[:5]]


def test_native_and_described_examples_agree() -> None:
    """Native examples and vgi.example_queries carry the same SQL and descriptions."""
    for fn in (SigmaMatchFunction, SigmaCheckFunction, SigmaRuleInfoFunction, SigmaMatchFieldsFunction):
        meta = fn.Meta  # type: ignore[attr-defined]
        native = [(ex.sql, ex.description) for ex in meta.examples]
        described = [(q["sql"], q["description"]) for q in json.loads(meta.tags["vgi.example_queries"])]
        assert native == described, fn.__name__
