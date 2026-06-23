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

from typing import Annotated

import pyarrow as pa
from vgi.arguments import Param, Returns
from vgi.metadata import FunctionExample
from vgi.scalar_function import ScalarFunction

from . import engine

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
