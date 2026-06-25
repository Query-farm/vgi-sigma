# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.8.5",
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
    SELECT sigma.sigma_match('{"EventID": 4625, "LogonType": 3}',
        'detection:
  selection:
    EventID: 4625
    LogonType: 3
  condition: selection');                                       -- true

    SELECT sigma.sigma_check('detection: {sel: {EventID: 1}, condition: sel}');
    SELECT * FROM sigma.sigma_rule_info('<rule yaml>');
    SELECT field FROM sigma.sigma_match_fields('<rule yaml>');
"""

from __future__ import annotations

import json

from vgi import Worker
from vgi.catalog import Catalog, Schema

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
    "# sigma\n\n"
    "Evaluate [Sigma](https://sigmahq.io) detection rules ('detection-as-code') against log/event "
    "rows directly in SQL, powered by [pySigma](https://github.com/SigmaHQ/pySigma).\n\n"
    "**Scalars:** `sigma_match` (does an event match a rule?), `sigma_check` (does a rule "
    "parse + compile?).\n\n"
    "**Table functions:** `sigma_rule_info` (rule metadata), `sigma_match_fields` (referenced "
    "event fields)."
)

_MAIN_DESCRIPTION_LLM = (
    "## sigma.main\n\n"
    "The single schema of the `sigma` catalog, holding every Sigma detection-rule function. Use "
    "it to bring SIEM-style 'detection-as-code' into SQL: compile a [Sigma](https://sigmahq.io) "
    "rule once and test it against an entire log/event table.\n\n"
    "**Functions.**\n\n"
    "- `sigma_match(event_json, rule_yaml)` (scalar) — does a JSON event match a rule? The "
    "headline predicate; apply per row over a log column.\n"
    "- `sigma_check(rule_yaml)` (scalar) — does a rule parse and compile with supported features? "
    "Never raises.\n"
    "- `sigma_rule_info(rule_yaml)` (table) — one row of rule header metadata (title, id, level, "
    "status, product/service, MITRE ATT&CK tags).\n"
    "- `sigma_match_fields(rule_yaml)` (table) — the event fields a rule references, for index "
    "and coverage planning.\n\n"
    "**Notes.** Every rule must include a non-empty `logsource:` block. Rules compile once per "
    "distinct text (cached), then evaluate per row, so a constant rule over a column is cheap."
)

_MAIN_DESCRIPTION_MD = (
    "# sigma.main\n\n"
    "Sigma detection-rule evaluation for SQL, powered by "
    "[pySigma](https://github.com/SigmaHQ/pySigma).\n\n"
    "## What's here\n\n"
    "| function | kind | purpose |\n"
    "|---|---|---|\n"
    "| `sigma_match` | scalar | True if a JSON event matches a rule. |\n"
    "| `sigma_check` | scalar | True if a rule parses + compiles. |\n"
    "| `sigma_rule_info` | table | One row of rule header metadata. |\n"
    "| `sigma_match_fields` | table | One row per referenced event field. |\n\n"
    "## Typical use\n\n"
    "```sql\n"
    "SELECT * FROM logs WHERE sigma.sigma_match(to_json(logs), :rule);\n"
    "```\n\n"
    "Every example rule carries a non-empty `logsource:` block, which pySigma requires."
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
}

# VGI506: representative, catalog-qualified example queries for the schema.
_SCHEMA_EXAMPLE_QUERIES = (
    'SELECT sigma.sigma_match(\'{"EventID": 4625, "LogonType": 3}\', '
    "'logsource: {service: security}\ndetection:\n  selection:\n    EventID: 4625\n"
    "  condition: selection');\n"
    "SELECT sigma.sigma_check('logsource: {service: security}\ndetection:\n  sel:\n"
    "    EventID: 1\n  condition: sel');\n"
    "SELECT title, level FROM sigma.sigma_rule_info('title: Failed Logon\nlevel: high\n"
    "logsource: {service: security}\ndetection:\n  sel:\n    EventID: 4625\n  condition: sel');\n"
    "SELECT field FROM sigma.sigma_match_fields('logsource: {service: security}\n"
    "detection:\n  sel:\n    EventID: 4625\n    LogonType: 3\n  condition: sel');"
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
    # VGI123 classifying tags (bare keys for faceting/discovery).
    "domain": "security",
    "category": "detection",
    "topic": "sigma-detection-rules",
}

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
