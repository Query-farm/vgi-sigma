"""Per-row scalar Sigma functions.

Both functions here are true DuckDB **scalars** -- one value (per row) in, one
value out -- so they can be used inline in any projection or predicate. The
headline pattern is testing a *constant* rule against a whole log column::

    SELECT * FROM logs WHERE sigma.sigma_match(to_json(logs), :rule);
    SELECT sigma.sigma_check(:rule);

A note on argument syntax
-------------------------
VGI / DuckDB *scalar* functions take **positional** arguments (the ``name :=
value`` named-argument syntax is a property of table functions and macros). Both
scalars here are plain positional functions.

The expensive work -- parsing + compiling the rule -- happens once per distinct
rule string (``engine.compile_rule`` is ``lru_cache``-d), so a constant rule
applied across a column compiles a single time and then evaluates per row.

NULL semantics: a NULL input row yields NULL output. A malformed *event* JSON in
``sigma_match`` yields ``false`` (a bad log row is a non-match, never a crash); a
malformed *rule* raises a clear error from ``sigma_match`` and yields ``false``
from ``sigma_check``.
"""

from __future__ import annotations

import json
from typing import Annotated

import pyarrow as pa
from vgi.arguments import Param, Returns
from vgi.metadata import FunctionExample
from vgi.scalar_function import ScalarFunction

from . import engine, meta

# A reusable brute-force rule (failed network logons), with the non-empty
# `logsource:` block pySigma requires. DuckDB single-quoted string literals.
_BRUTE_RULE_SQL = (
    "'title: Failed Network Logon\n"
    "logsource: {service: security}\n"
    "detection:\n"
    "  selection:\n"
    "    EventID: 4625\n"
    "    LogonType: 3\n"
    "  condition: selection'"
)

# VGI509: a JSON list of guaranteed-runnable, catalog-qualified examples. Each
# `sql` is self-contained and re-runnable against an attached `sigma` worker. We
# deliberately omit `expected_result` -- the linter only needs each query to
# execute cleanly.
_MATCH_EXECUTABLE_EXAMPLES = json.dumps(
    [
        {
            "description": (
                "A failed-logon event (EventID 4625, network logon type 3) matches a brute-force detection rule."
            ),
            "sql": (
                'SELECT sigma.sigma_match(\'{"EventID": 4625, "LogonType": 3}\', ' + _BRUTE_RULE_SQL + ") AS matched"
            ),
        },
        {
            "description": "An unrelated process-creation event does not match the same rule.",
            "sql": ("SELECT sigma.sigma_match('{\"EventID\": 1}', " + _BRUTE_RULE_SQL + ") AS matched"),
        },
    ]
)


# ===========================================================================
# sigma_match -- does this JSON event match this Sigma rule?
# ===========================================================================


class SigmaMatchFunction(ScalarFunction):
    """``sigma_match(event_json, rule_yaml)`` -- does the event match the rule?"""

    class Meta:
        """VGI function metadata for ``sigma_match``."""

        name = "sigma_match"
        description = (
            "True if the JSON event matches the Sigma rule. Use per-row over a log "
            "column: WHERE sigma_match(to_json(t), rule)."
        )
        categories = ["sigma", "detect"]
        tags = meta.object_tags(
            title="Sigma Rule Event Match",
            doc_llm=(
                "## sigma_match(event_json, rule_yaml)\n\n"
                "Tests whether a single log/event row, supplied as a JSON object string, "
                "matches a [Sigma](https://sigmahq.io) detection rule supplied as YAML. This is "
                "the headline function of the catalog: it turns 'detection-as-code' into a SQL "
                "predicate so you can hunt for a known threat across an entire log table.\n\n"
                "**When to use it.** Apply it per row over a log column to find matching events, "
                "typically in a `WHERE` clause: "
                "`WHERE sigma.sigma_match(to_json(t), :rule)`. The rule is parsed and compiled "
                "exactly once per distinct rule string (the engine is `lru_cache`-d), so scanning "
                "one constant rule across millions of rows compiles a single time and then "
                "evaluates the boolean condition tree per row.\n\n"
                "**Inputs.** `event_json` — the event as a JSON object string (e.g. from "
                "`to_json(row)`); `rule_yaml` — a complete Sigma rule, which must include a "
                "non-empty `logsource:` block and a `detection:` section with a `condition`.\n\n"
                "**Output & edge cases.** Returns `BOOLEAN`. A NULL input row yields NULL. A "
                "malformed *event* JSON yields `false` (one bad log row is a non-match, never a "
                "crash), but a malformed or unsupported *rule* raises a clear error so you never "
                "silently mis-evaluate. Supported leaf forms include field/value comparisons "
                "(equals, contains, startswith, endswith, regex, wildcards) and bare keyword "
                "searches; selector forms like `1 of selection_*` and `all of them` are expanded "
                "by pySigma and work for free."
            ),
            doc_md=(
                "# sigma_match\n\n"
                "Returns `true` when a JSON event matches a Sigma detection rule. It is the core "
                "matcher for SIEM-style threat detection directly in SQL.\n\n"
                "## Usage\n\n"
                "```sql\n"
                "SELECT * FROM logs\n"
                "WHERE sigma.sigma_match(to_json(logs), :rule);\n"
                "```\n\n"
                "## Arguments\n\n"
                "| name | type | description |\n"
                "|---|---|---|\n"
                "| `event_json` | VARCHAR | The event as a JSON object string. |\n"
                "| `rule_yaml` | VARCHAR | A Sigma rule (YAML) with a non-empty `logsource:`. |\n\n"
                "## Notes\n\n"
                "- A malformed *event* returns `false`; a malformed *rule* raises a clear error.\n"
                "- NULL in, NULL out.\n"
                "- The rule compiles once per distinct string, then evaluates per row, so a "
                "constant rule over a whole column is cheap."
            ),
            keywords=(
                "sigma, sigma_match, detection, detect, SIEM, threat hunting, rule match, "
                "event match, log analysis, detection-as-code, EDR, security"
            ),
            relative_path="vgi_sigma/scalars.py",
        ) | {"vgi.executable_examples": _MATCH_EXECUTABLE_EXAMPLES}
        examples = [
            FunctionExample(
                sql=(
                    'SELECT sigma.sigma_match(\'{"EventID": 4625, "LogonType": 3}\', '
                    "'logsource: {service: security}\\ndetection:\\n  selection:\\n"
                    "    EventID: 4625\\n  condition: selection')"
                ),
                description="Does an event match a Sigma rule? (-> true)",
            ),
        ]

    @classmethod
    def compute(
        cls,
        event_json: Annotated[pa.StringArray, Param(doc="The event, as a JSON object string.")],
        rule_yaml: Annotated[pa.StringArray, Param(doc="The Sigma rule, as YAML.")],
    ) -> Annotated[pa.BooleanArray, Returns()]:
        """Return, per row, whether the JSON event matches the Sigma rule."""
        events = event_json.to_pylist()
        rules = rule_yaml.to_pylist()
        out = [engine.match(e, r) for e, r in zip(events, rules, strict=True)]
        return pa.array(out, type=pa.bool_())


# ===========================================================================
# sigma_check -- does this rule parse / compile?
# ===========================================================================


class SigmaCheckFunction(ScalarFunction):
    """``sigma_check(rule_yaml)`` -- does the rule parse + compile (supported)?"""

    class Meta:
        """VGI function metadata for ``sigma_check``."""

        name = "sigma_check"
        description = (
            "True if the Sigma rule parses and compiles with only supported modifiers; "
            "false for malformed YAML or unsupported features."
        )
        categories = ["sigma", "validate"]
        tags = meta.object_tags(
            title="Sigma Rule Validity Check",
            doc_llm=(
                "## sigma_check(rule_yaml)\n\n"
                "Returns `true` when a [Sigma](https://sigmahq.io) rule (YAML) parses and "
                "compiles successfully using only features this worker supports, and `false` "
                "otherwise. Unlike `sigma_match`, it **never raises** -- it is the safe, "
                "boolean-returning gate you run before trusting a rule.\n\n"
                "**When to use it.** Validate rules in bulk -- e.g. lint a column of candidate "
                "rules, filter a detection-rule repository down to the ones this engine can "
                "actually evaluate, or guard a pipeline with "
                "`WHERE sigma.sigma_check(rule_text)` before feeding rules to `sigma_match`.\n\n"
                "**Inputs.** `rule_yaml` -- a complete Sigma rule. Remember that pySigma requires "
                "a non-empty `logsource:` block; a rule missing it (or with `logsource: {}`) is "
                "invalid and returns `false`.\n\n"
                "**Output & edge cases.** Returns `BOOLEAN`; NULL in, NULL out. It returns "
                "`false` for malformed YAML, a missing `logsource:`, a missing `condition`, or "
                "any unsupported modifier. Because it swallows errors into `false`, use "
                "`sigma_rule_info` if you need the specific parse error surfaced."
            ),
            doc_md=(
                "# sigma_check\n\n"
                "A non-raising validator: returns `true` when a Sigma rule parses and compiles "
                "with only supported features, `false` otherwise.\n\n"
                "## Usage\n\n"
                "```sql\n"
                "SELECT rule_id\n"
                "FROM candidate_rules\n"
                "WHERE NOT sigma.sigma_check(rule_text);  -- find rules we cannot evaluate\n"
                "```\n\n"
                "## Arguments\n\n"
                "| name | type | description |\n"
                "|---|---|---|\n"
                "| `rule_yaml` | VARCHAR | A Sigma rule (YAML) to validate. |\n\n"
                "## Notes\n\n"
                "- A rule **must** have a non-empty `logsource:` block, or it is invalid.\n"
                "- Never raises -- malformed or unsupported rules simply return `false`.\n"
                "- NULL in, NULL out."
            ),
            keywords=(
                "sigma, sigma_check, validate, lint, rule validation, compile, parse, "
                "supported features, detection-as-code, security"
            ),
            relative_path="vgi_sigma/scalars.py",
        )
        examples = [
            FunctionExample(
                sql=(
                    "SELECT sigma.sigma_check('logsource: {service: security}\\n"
                    "detection:\\n  selection:\\n    EventID: 4625\\n  condition: selection')"
                ),
                description="Validate a Sigma rule (-> true)",
            ),
            FunctionExample(
                sql="SELECT sigma.sigma_check('not: a: valid: rule')",
                description="Invalid rule (-> false)",
            ),
        ]

    @classmethod
    def compute(
        cls,
        rule_yaml: Annotated[pa.StringArray, Param(doc="The Sigma rule, as YAML.")],
    ) -> Annotated[pa.BooleanArray, Returns()]:
        """Return, per row, whether the Sigma rule parses and compiles."""
        out = [engine.check(r) for r in rule_yaml.to_pylist()]
        return pa.array(out, type=pa.bool_())


SCALAR_FUNCTIONS: list[type] = [
    SigmaMatchFunction,
    SigmaCheckFunction,
]
