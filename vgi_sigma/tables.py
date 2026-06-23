"""Set-returning Sigma table functions for DuckDB.

These expand to rows from a single rule argument, so they are exposed as **table
functions** (the form that accepts DuckDB ``name := value`` arguments -- though
both here take only the positional rule). The per-row, single-value functions
(``sigma_match``, ``sigma_check``) are *scalars* and live in
:mod:`vgi_sigma.scalars`.

    SELECT * FROM sigma.sigma_rule_info('<rule yaml>');
    SELECT field FROM sigma.sigma_match_fields('<rule yaml>');

A NULL rule yields no rows; a malformed rule raises a clear error (these are
introspection helpers run against a known rule, not a per-row scan).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, ClassVar

import pyarrow as pa
from vgi.arguments import Arg
from vgi.metadata import FunctionExample
from vgi.table_function import (
    BindParams,
    ProcessParams,
    TableCardinality,
    TableFunctionGenerator,
    bind_fixed_schema,
    init_single_worker,
)
from vgi_rpc.rpc import OutputCollector

from . import engine
from .schema_utils import field


@dataclass(kw_only=True)
class _RuleArg:
    """A single positional ``rule_yaml`` argument."""

    rule_yaml: Annotated[str, Arg(0, arrow_type=pa.string(), doc="The Sigma rule, as YAML.")]


# ===========================================================================
# sigma_rule_info -- one row of rule metadata
# ===========================================================================

_RULE_INFO_SCHEMA = pa.schema(
    [
        field("title", pa.string(), "Rule title.", nullable=True),
        field("id", pa.string(), "Rule UUID (the 'id' field).", nullable=True),
        field("level", pa.string(), "Severity: informational/low/medium/high/critical.", nullable=True),
        field("status", pa.string(), "Lifecycle status: stable/test/experimental/...", nullable=True),
        field("description", pa.string(), "Human-readable description.", nullable=True),
        field("product", pa.string(), "logsource product, e.g. 'windows'.", nullable=True),
        field("service", pa.string(), "logsource service, e.g. 'security'.", nullable=True),
        field("tags", pa.list_(pa.string()), "Rule tags, e.g. 'attack.t1110'.", nullable=True),
    ]
)


@init_single_worker
@bind_fixed_schema
class SigmaRuleInfoFunction(TableFunctionGenerator[_RuleArg]):
    """One row of metadata for a Sigma rule (title, id, level, ..., tags).

    NULL rule -> no rows. A malformed rule raises a clear parse error.
    """

    FIXED_SCHEMA: ClassVar[pa.Schema] = _RULE_INFO_SCHEMA

    class Meta:
        name = "sigma_rule_info"
        description = (
            "One row of rule metadata: title, id, level, status, description, product, service, tags"
        )
        categories = ["sigma", "metadata"]
        examples = [
            FunctionExample(
                sql=(
                    "SELECT title, level FROM sigma.sigma_rule_info("
                    "'title: T\\nlevel: high\\nlogsource: {service: security}\\n"
                    "detection:\\n  sel:\\n    EventID: 1\\n  condition: sel')"
                ),
                description="Read a rule's title and severity",
            ),
            FunctionExample(
                sql=(
                    "SELECT UNNEST(tags) AS tag FROM sigma.sigma_rule_info("
                    "'title: T\\ntags: [attack.t1110]\\nlogsource: {service: security}\\n"
                    "detection:\\n  sel:\\n    EventID: 1\\n  condition: sel')"
                ),
                description="Expand a rule's MITRE ATT&CK tags",
            ),
        ]

    @classmethod
    def cardinality(cls, params: BindParams[_RuleArg]) -> TableCardinality:
        return TableCardinality(estimate=1, max=1)

    @classmethod
    def process(cls, params: ProcessParams[_RuleArg], state: None, out: OutputCollector) -> None:
        info = engine.rule_info(params.args.rule_yaml)
        if info is not None:
            out.emit(
                pa.RecordBatch.from_pydict(
                    {
                        "title": [info.title],
                        "id": [info.id],
                        "level": [info.level],
                        "status": [info.status],
                        "description": [info.description],
                        "product": [info.product],
                        "service": [info.service],
                        "tags": [info.tags],
                    },
                    schema=params.output_schema,
                )
            )
        out.finish()


# ===========================================================================
# sigma_match_fields -- one row per referenced event field
# ===========================================================================

_MATCH_FIELDS_SCHEMA = pa.schema(
    [field("field", pa.string(), "An event field the rule references.", nullable=False)]
)


@init_single_worker
@bind_fixed_schema
class SigmaMatchFieldsFunction(TableFunctionGenerator[_RuleArg]):
    """The event fields a rule references, one per row (for index/coverage planning).

    NULL rule -> no rows. A malformed rule raises a clear parse error.
    """

    FIXED_SCHEMA: ClassVar[pa.Schema] = _MATCH_FIELDS_SCHEMA

    class Meta:
        name = "sigma_match_fields"
        description = "One row per event field the rule references (for index/coverage planning)"
        categories = ["sigma", "metadata"]
        examples = [
            FunctionExample(
                sql=(
                    "SELECT field FROM sigma.sigma_match_fields("
                    "'logsource: {service: security}\\ndetection:\\n  sel:\\n"
                    "    EventID: 4625\\n    LogonType: 3\\n  condition: sel')"
                ),
                description="List the fields a rule keys on (-> EventID, LogonType)",
            ),
        ]

    @classmethod
    def cardinality(cls, params: BindParams[_RuleArg]) -> TableCardinality:
        return TableCardinality(estimate=4, max=None)

    @classmethod
    def process(cls, params: ProcessParams[_RuleArg], state: None, out: OutputCollector) -> None:
        fields = engine.match_fields(params.args.rule_yaml)
        if fields is not None:
            out.emit(pa.RecordBatch.from_pydict({"field": fields}, schema=params.output_schema))
        out.finish()


TABLE_FUNCTIONS: list[type] = [
    SigmaRuleInfoFunction,
    SigmaMatchFieldsFunction,
]
