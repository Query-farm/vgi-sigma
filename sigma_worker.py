# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.16.0",
#     "pysigma>=0.11",
# ]
# ///
"""VGI worker exposing Sigma detection-rule evaluation to SQL.

Assembles the functions in ``vgi_sigma`` into a single ``sigma`` catalog and
runs the worker over stdio (DuckDB subprocess) or HTTP. It evaluates
`Sigma <https://sigmahq.io>`_ detection rules ("detection-as-code") against
log/event rows: compile a rule once, then test it against every row of a log
table. A defensive security tool, completing Query Farm's cyber cluster
(vgi-yara / vgi-ioc / vgi-cve / vgi-pe / vgi-x509).

Usage:
    uv run sigma_worker.py               # serve over stdio (DuckDB subprocess)

    INSTALL vgi FROM community; LOAD vgi;
    ATTACH 'sigma' (TYPE vgi, LOCATION 'uv run sigma_worker.py');

    -- Does an event match a rule? (the headline; use per-row over a log column)
    -- Every rule needs a title and a non-empty logsource: block.
    SELECT sigma.sigma_match('{"EventID": 4625, "LogonType": 3}',
        'title: Failed Network Logon
logsource: {service: security}
detection:
  selection:
    EventID: 4625
    LogonType: 3
  condition: selection');                                       -- true

    SELECT sigma.sigma_check('title: Process Create
logsource: {service: security}
detection: {sel: {EventID: 1}, condition: sel}');
    SELECT * FROM sigma.sigma_rule_info('<rule yaml>');
    SELECT field FROM sigma.sigma_match_fields('<rule yaml>');
"""

from __future__ import annotations

import json

from vgi import Worker
from vgi.catalog import Catalog, Schema, View

from vgi_sigma import engine
from vgi_sigma.scalars import SCALAR_FUNCTIONS
from vgi_sigma.tables import TABLE_FUNCTIONS

_FUNCTIONS: list[type] = [
    *SCALAR_FUNCTIONS,
    *TABLE_FUNCTIONS,
]

_CATALOG_DESCRIPTION_LLM = (
    "Evaluate Sigma detection rules ('detection-as-code') against log/event rows directly in SQL, "
    "backed by pySigma. Test whether a JSON event matches a Sigma rule per-row over a whole log "
    "column (sigma_match), validate that a rule parses and compiles with only supported features "
    "(sigma_check), read a rule's metadata such as title, id, severity level, status, description, "
    "logsource product/service, and MITRE ATT&CK tags (sigma_rule_info), and list the event fields a "
    "rule keys on for index and coverage planning (sigma_match_fields). A rule is compiled once and "
    "evaluated per row, so a constant rule scanned across a log table is cheap. Use for SIEM-style "
    "threat detection, rule triage, and coverage analysis over event/log tables in SQL."
)

_CATALOG_DESCRIPTION_MD = (
    "# Sigma Detection Rules in SQL\n\n"
    "![Sigma logo](https://raw.githubusercontent.com/SigmaHQ/sigma/master/images/Sigma_0.3.png)\n\n"
    "Run [Sigma](https://sigmahq.io) detection rules — the open, vendor-neutral standard for "
    "**detection-as-code** — directly over your log and event tables in SQL, powered by "
    "[pySigma](https://github.com/SigmaHQ/pySigma).\n\n"
    "This extension brings SIEM-style threat detection and threat hunting into DuckDB. If you have "
    "events as rows (Windows Security logs, EDR telemetry, cloud audit trails, web/proxy logs, or "
    'any JSON records), you can take a Sigma rule and ask, per row, "does this event match?" — '
    "without exporting data to a separate SIEM. It is built for detection engineers, threat "
    "hunters, incident responders, and data engineers who want to test, triage, and measure "
    "detection coverage where the data already lives. It is a defensive security tool and part of "
    "Query Farm's cyber analytics cluster alongside YARA, IOC, CVE, PE, and X.509 workers.\n\n"
    "Under the hood, each rule's YAML is parsed and compiled once by pySigma — the reference Sigma "
    "implementation maintained by [SigmaHQ](https://github.com/SigmaHQ/sigma) — into a boolean "
    "condition tree, then evaluated against every row. Compilation is cached by rule text, so a "
    "constant rule scanned across a whole log column compiles a single time and only the per-row "
    "match runs hot, keeping column scans cheap. The evaluator honors Sigma field modifiers "
    "(contains, startswith, endswith, regex, and the rest), wildcard string matching, numeric, "
    "boolean and null values, and the full selector grammar (`1 of selection_*`, `all of them`, "
    "and friends). Rules and their metadata, including [MITRE ATT&CK](https://attack.mitre.org) "
    "tags, are read straight from the rule text.\n\n"
    "The workflow is deliberately simple: keep your events as rows, express detection logic as "
    "Sigma YAML, and evaluate one against the other as an ordinary SQL predicate. Because a "
    "constant rule compiles once and only the boolean match runs per row, applying a detection "
    "across a whole log column stays cheap enough to run interactively. Beyond matching, the "
    "catalog also lets you validate a rule library before you trust it, and introspect a rule's "
    "header metadata and referenced fields for triage, index planning, and coverage analysis — so "
    "a single attached worker covers the detect / validate / plan loop of detection engineering.\n\n"
    "A typical hunt applies a matcher predicate per row over a log table (for example in a "
    "`WHERE` clause against `to_json(row)`), while separate helpers validate that a rule library "
    "compiles and introspect rule metadata and referenced fields for planning. A browsable "
    "discovery table lists the field modifiers the evaluator supports.\n\n"
    "Learn more from the [Sigma documentation](https://sigmahq.io/docs/), the "
    "[pySigma reference docs](https://sigmahq-pysigma.readthedocs.io), and the "
    "[pySigma source repository](https://github.com/SigmaHQ/pySigma)."
)

_MAIN_DESCRIPTION_LLM = (
    "## sigma.main\n\n"
    "The single schema of the `sigma` catalog, bringing SIEM-style 'detection-as-code' into SQL. "
    "Use it to compile a [Sigma](https://sigmahq.io) rule once and test it against an entire "
    "log/event table, all without leaving the database.\n\n"
    "**What it's for.** The schema spans the everyday loop of detection engineering: match events "
    "against a rule to hunt for a known threat, validate that a rule library parses and compiles "
    "before you trust it, and introspect a rule's header metadata and the fields it keys on for "
    "triage, index planning, and MITRE ATT&CK coverage analysis. Matching is the hot path and the "
    "usual entry point; validation and introspection support it around the edges.\n\n"
    "**Notes.** Every rule must include a non-empty `logsource:` block. Rules compile once per "
    "distinct text (cached), then evaluate per row, so a constant rule over a column is cheap. "
    "Events are supplied as JSON object strings (e.g. from `to_json(row)`)."
)

_MAIN_DESCRIPTION_MD = (
    "# sigma.main\n\n"
    "Sigma detection-rule evaluation for SQL, powered by "
    "[pySigma](https://github.com/SigmaHQ/pySigma).\n\n"
    "## What it covers\n\n"
    "This schema turns Sigma 'detection-as-code' into ordinary SQL. It supports the everyday "
    "detection-engineering loop directly over your log tables:\n\n"
    "- **Detect** — test log/event rows against a rule to hunt for a known threat.\n"
    "- **Validate** — confirm a rule library parses and compiles before you rely on it.\n"
    "- **Plan** — introspect a rule's header metadata and the fields it references for triage, "
    "index planning, and coverage analysis.\n\n"
    "List the schema to browse the individual functions; each ships its own documentation and "
    "runnable examples. A browsable discovery table lists the Sigma field modifiers the "
    "evaluator understands, so you can review them before authoring a rule.\n\n"
    "## Typical use\n\n"
    "Apply a matcher predicate per row over a log table (typically in a `WHERE` clause against "
    "`to_json(row)`), and use the validation and introspection helpers to check a rule library "
    "and plan coverage. Every attached example query is fully catalog-qualified and runnable.\n\n"
    "Every example rule carries a non-empty `logsource:` block, which pySigma requires."
)

# VGI152/VGI920: a fixed suite of analyst tasks `vgi-lint simulate` grades. The
# analyst sees only each task's prompt (never the reference SQL) and must drive
# the worker to the same result. References are deterministic; where column
# names or row order aren't pinned by the prompt we set ignore_column_names /
# unordered so a correct answer isn't failed on cosmetics.
_AGENT_TEST_TASKS = json.dumps(
    [
        {
            "name": "match-failed-network-logon",
            "prompt": (
                "You have a single Windows security event, the JSON object "
                '{"EventID": 4625, "LogonType": 3}. Determine whether it matches a Sigma '
                "detection rule for failed network logons — one whose selection requires "
                "EventID 4625 and LogonType 3. Return a single boolean value."
            ),
            "reference_sql": (
                'SELECT sigma.main.sigma_match(\'{"EventID": 4625, "LogonType": 3}\', '
                "'{title: Failed Network Logon, logsource: {service: security}, "
                "detection: {selection: {EventID: 4625, LogonType: 3}, condition: selection}}') AS matched"
            ),
            "ignore_column_names": True,
        },
        {
            "name": "validate-sigma-rule",
            "prompt": (
                "Check whether a Sigma rule is valid — i.e. it parses and compiles using only "
                "supported features — without evaluating it against any event. Use this rule: "
                "title 'Failed Logon', a security logsource, and a selection matching EventID "
                "4625 with condition 'selection'. Return a single boolean value."
            ),
            "reference_sql": (
                "SELECT sigma.main.sigma_check("
                "'{title: Failed Logon, logsource: {service: security}, "
                "detection: {selection: {EventID: 4625}, condition: selection}}') AS valid"
            ),
            "ignore_column_names": True,
        },
        {
            "name": "read-rule-title-and-level",
            "prompt": (
                "Read the header metadata of a Sigma rule and return its title and severity "
                "level. The rule has title 'Failed Logon', level 'high', a security logsource, "
                "and a selection matching EventID 4625 with condition 'selection'."
            ),
            "reference_sql": (
                "SELECT title, level FROM sigma.main.sigma_rule_info("
                "'{title: Failed Logon, level: high, logsource: {service: security}, "
                "detection: {selection: {EventID: 4625}, condition: selection}}')"
            ),
            "ignore_column_names": True,
        },
        {
            "name": "list-referenced-fields",
            "prompt": (
                "List the distinct event field names that a Sigma rule keys on, so an analyst "
                "knows which log columns must be present. Use a rule titled 'Failed Network "
                "Logon' with a security logsource, whose selection matches EventID 4625 and "
                "LogonType 3, with condition 'selection'. Return the field names."
            ),
            "reference_sql": (
                "SELECT field FROM sigma.main.sigma_match_fields("
                "'{title: Failed Network Logon, logsource: {service: security}, "
                "detection: {selection: {EventID: 4625, LogonType: 3}, condition: selection}}')"
            ),
            "unordered": True,
            "ignore_column_names": True,
        },
        {
            "name": "count-supported-modifiers",
            "prompt": (
                "The worker publishes a browsable discovery table listing every Sigma field "
                "modifier its evaluator understands. Using that table, how many distinct "
                "modifiers of kind 'affix' does the engine support? Return a single number."
            ),
            "reference_sql": (
                "SELECT count(*) AS affix_modifiers FROM sigma.main.supported_modifiers WHERE kind = 'affix'"
            ),
            "ignore_column_names": True,
        },
    ]
)

_CATALOG_TAGS = {
    "vgi.title": "Sigma Detection-Rule Evaluation",
    "vgi.keywords": json.dumps(
        [
            "sigma",
            "detection rules",
            "detection-as-code",
            "SIEM",
            "threat detection",
            "threat hunting",
            "log analysis",
            "event matching",
            "MITRE ATT&CK",
            "pySigma",
            "security",
            "defensive",
        ]
    ),
    "vgi.doc_llm": _CATALOG_DESCRIPTION_LLM,
    "vgi.doc_md": _CATALOG_DESCRIPTION_MD,
    "vgi.author": "Query.Farm",
    "vgi.copyright": "Copyright 2026 Query Farm LLC - https://query.farm",
    "vgi.license": "MIT",
    "vgi.support_contact": "https://github.com/Query-farm/vgi-sigma/issues",
    "vgi.support_policy_url": "https://github.com/Query-farm/vgi-sigma/blob/main/README.md",
    # VGI152/VGI920: analyst-task suite for `vgi-lint simulate`.
    "vgi.agent_test_tasks": _AGENT_TEST_TASKS,
}

# VGI506/VGI515: representative, fully catalog-qualified example queries for the
# schema, as a JSON list of {description, sql} so each carries a human-readable
# description (the native examples carrier drops descriptions). Each rule is
# written as single-line YAML flow syntax so it lives cleanly inside a
# single-quoted SQL string literal (no newline escaping) and runs as-is.
_SCHEMA_EXAMPLE_QUERIES = json.dumps(
    [
        {
            "description": "Does a failed-network-logon event match a brute-force detection rule?",
            "sql": (
                'SELECT sigma.main.sigma_match(\'{"EventID": 4625, "LogonType": 3}\', '
                "'{title: Failed Network Logon, logsource: {service: security}, "
                "detection: {selection: {EventID: 4625, LogonType: 3}, condition: selection}}') AS matched"
            ),
        },
        {
            "description": "Validate that a process-creation rule parses and compiles.",
            "sql": (
                "SELECT sigma.main.sigma_check("
                "'{title: Process Create, logsource: {service: security}, "
                "detection: {sel: {EventID: 1}, condition: sel}}') AS valid"
            ),
        },
        {
            "description": "Read a rule's title and severity level from its header metadata.",
            "sql": (
                "SELECT title, level FROM sigma.main.sigma_rule_info("
                "'{title: Failed Logon, level: high, logsource: {service: security}, "
                "detection: {sel: {EventID: 4625}, condition: sel}}')"
            ),
        },
        {
            "description": "List the event fields a rule keys on, for index and coverage planning.",
            "sql": (
                "SELECT field FROM sigma.main.sigma_match_fields("
                "'{title: Failed Network Logon, logsource: {service: security}, "
                "detection: {sel: {EventID: 4625, LogonType: 3}, condition: sel}}') ORDER BY field"
            ),
        },
        {
            "description": "Browse the field modifiers the evaluator supports.",
            "sql": "SELECT modifier, kind FROM sigma.main.supported_modifiers ORDER BY modifier",
        },
    ]
)

# VGI413: ordered navigation registry for the schema. Each object declares one
# primary `vgi.category` naming one of these (VGI409/VGI411), and every category
# must have at least one member (VGI412).
_SCHEMA_CATEGORIES = json.dumps(
    [
        {
            "name": "detection",
            "title": "Threat Detection",
            "description": "Match log/event rows against a Sigma rule to hunt for known threats.",
            "keywords": ["match", "detect", "threat hunting", "SIEM"],
        },
        {
            "name": "validation",
            "title": "Rule Validation",
            "description": "Check that a Sigma rule parses and compiles with only supported features.",
            "keywords": ["validate", "lint", "compile", "parse"],
        },
        {
            "name": "introspection",
            "title": "Rule Introspection",
            "description": "Read a rule's header metadata and the event fields it references for triage and planning.",
            "keywords": ["metadata", "fields", "triage", "coverage", "index planning"],
        },
        {
            "name": "reference",
            "title": "Engine Reference",
            "description": (
                "Browsable reference tables describing evaluator capabilities, e.g. the Sigma field modifiers."
            ),
            "keywords": ["reference", "modifiers", "supported features", "discovery", "capabilities"],
        },
    ]
)

# Per-schema discovery/description + VGI123 classifying tags. Note the
# classifying keys (domain/category/topic) are BARE, not vgi.-namespaced.
_SCHEMA_TAGS = {
    "vgi.title": "Sigma — main",
    "vgi.keywords": json.dumps(
        [
            "sigma",
            "sigma_match",
            "sigma_check",
            "sigma_rule_info",
            "sigma_match_fields",
            "detection",
            "SIEM",
            "threat detection",
            "log analysis",
            "detection-as-code",
            "MITRE ATT&CK",
        ]
    ),
    "vgi.doc_llm": _MAIN_DESCRIPTION_LLM,
    "vgi.doc_md": _MAIN_DESCRIPTION_MD,
    "vgi.example_queries": _SCHEMA_EXAMPLE_QUERIES,
    # VGI413: navigation registry; each object names one of these via vgi.category.
    "vgi.categories": _SCHEMA_CATEGORIES,
    # VGI123 classifying tags (bare keys for faceting/discovery).
    "domain": "security",
    "category": "detection",
    "topic": "sigma-detection-rules",
}


def _modifiers_values_sql() -> str:
    """Build a self-contained ``VALUES`` relation of every supported modifier.

    Rows come from :func:`engine.supported_modifiers` -- the engine's own
    registry -- so the browsable view and the evaluator's behaviour can never
    drift. Emitting literal rows keeps the view a genuine, credential-free
    browsable relation: it resolves without parsing or evaluating any rule.
    """
    rows = ",\n        ".join(
        "('{}', '{}', '{}')".format(mod, kind, desc.replace("'", "''"))
        for mod, kind, desc in engine.supported_modifiers()
    )
    return f"SELECT modifier, kind, description FROM (VALUES\n        {rows}\n    ) AS t(modifier, kind, description)"


# VGI146: a genuinely browsable relation (not a parameterless table function,
# which would trip VGI145) so an agent can discover the engine's capabilities
# without first guessing rule arguments. Backed by a literal ``VALUES`` relation
# generated from `engine.supported_modifiers()`, so it scans credential-free
# (clearing VGI911) and stays in lockstep with the evaluator.
_SUPPORTED_MODIFIERS_VIEW = View(
    name="supported_modifiers",
    definition=_modifiers_values_sql(),
    comment="Every Sigma field modifier the evaluator implements, one per row (discovery table).",
    column_comments={
        "modifier": (
            "The modifier keyword as written in a rule (e.g. `contains`); `plain` is the "
            "default, modifier-free comparison."
        ),
        "kind": "Modifier family: `equality`, `affix`, `regex`, or `combiner`.",
        "description": "What the modifier does when matching an event value.",
    },
    tags={
        "vgi.title": "Supported Sigma Modifiers",
        "vgi.doc_llm": (
            "A ready-to-scan **discovery table** of every Sigma field modifier this worker's "
            "evaluator understands, so you can check what a rule may use before authoring or "
            "trusting it. Browse the view directly (no arguments): the `modifier` column holds "
            "the keyword written after a pipe in a rule field (e.g. `CommandLine|contains`), "
            "with the `plain` row standing for the default modifier-free comparison; `kind` "
            "groups them into `equality`, `affix`, `startswith`/`endswith` style, `regex`, and "
            "the `all` `combiner`; and `description` explains the matching semantics. A rule "
            "that uses any modifier absent from this table is rejected by `sigma_check` and "
            "raises from `sigma_match`, so this is the authoritative capability list. Rows are "
            "generated from the evaluator's own registry, so the view can never drift from "
            "actual behaviour. Runnable browse and filter queries are attached as examples."
        ),
        "vgi.doc_md": (
            "# supported_modifiers (view)\n\n"
            "Every Sigma field modifier the evaluator implements, as a plain browsable table.\n\n"
            "The `modifier` column is the keyword written after a pipe on a rule field "
            "(`CommandLine|contains`, `Image|endswith`); the `plain` row is the default "
            "modifier-free comparison. The `kind` column groups modifiers into `equality`, "
            "`affix`, `regex`, and `combiner` families, and `description` explains the matching "
            "semantics. A rule using any modifier not listed here is rejected by `sigma_check` "
            "and raises from `sigma_match`, so this view is the authoritative capability list. "
            "The rows are generated from the evaluator's own registry, so they stay in lockstep "
            "with behaviour: filter by `kind` to review a family, or probe for a specific "
            "`modifier` before authoring a rule that uses it."
        ),
        "vgi.keywords": json.dumps(
            [
                "supported modifiers",
                "sigma modifiers",
                "field modifiers",
                "contains",
                "startswith",
                "endswith",
                "regex",
                "capabilities",
                "discovery",
                "supported features",
            ]
        ),
        "vgi.category": "reference",  # VGI409/411: primary category in sigma.main's registry
        # VGI123 classifying tags (bare keys for faceting/discovery).
        "domain": "security",
        "category": "detection",
        "topic": "sigma-modifiers",
        # VGI502: object/view-level example_queries is a JSON array of {description, sql}.
        "vgi.example_queries": json.dumps(
            [
                {
                    "description": "List every supported Sigma field modifier and its family.",
                    "sql": "SELECT modifier, kind FROM sigma.main.supported_modifiers ORDER BY modifier",
                },
                {
                    "description": "Show only the affix modifiers (contains / startswith / endswith).",
                    "sql": (
                        "SELECT modifier, description FROM sigma.main.supported_modifiers "
                        "WHERE kind = 'affix' ORDER BY modifier"
                    ),
                },
                {
                    "description": "Is the regular-expression modifier supported?",
                    "sql": "SELECT count(*) > 0 AS has_regex FROM sigma.main.supported_modifiers WHERE modifier = 're'",
                },
            ]
        ),
    },
)


_SIGMA_CATALOG = Catalog(
    name="sigma",
    default_schema="main",
    comment="Evaluate Sigma detection rules against log/event rows for SQL, powered by pySigma",
    source_url="https://github.com/Query-farm/vgi-sigma",
    tags=_CATALOG_TAGS,
    schemas=[
        Schema(
            name="main",
            comment="Evaluate, validate, and introspect Sigma detection rules over log/event rows",
            tags=_SCHEMA_TAGS,
            views=[_SUPPORTED_MODIFIERS_VIEW],
            functions=list(_FUNCTIONS),
        ),
    ],
)


class SigmaWorker(Worker):
    """Worker process hosting the ``sigma`` catalog."""

    catalog = _SIGMA_CATALOG


def main() -> None:
    """Run the sigma worker process (stdio or, via flags, HTTP)."""
    SigmaWorker.main()


if __name__ == "__main__":
    main()
