# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.8.4",
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
    "Sigma detection-rule functions over log/event rows: sigma_match and sigma_check (per-row "
    "scalars) plus sigma_rule_info and sigma_match_fields (table functions returning rule metadata "
    "and the event fields a rule references)."
)

_MAIN_DESCRIPTION_MD = (
    "Sigma detection-rule evaluation functions powered by pySigma: `sigma_match`, `sigma_check`, "
    "`sigma_rule_info`, `sigma_match_fields`."
)

_CATALOG_TAGS = {
    "vgi.description_llm": _CATALOG_DESCRIPTION_LLM,
    "vgi.description_md": _CATALOG_DESCRIPTION_MD,
    "vgi.author": "Query.Farm",
    "vgi.copyright": "Copyright 2026 Query Farm LLC - https://query.farm",
    "vgi.license": "MIT",
    "vgi.support_contact": "https://github.com/Query-farm/vgi-sigma/issues",
    "vgi.support_policy_url": "https://github.com/Query-farm/vgi-sigma/blob/main/README.md",
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
            tags={
                "vgi.description_llm": _MAIN_DESCRIPTION_LLM,
                "vgi.description_md": _MAIN_DESCRIPTION_MD,
            },
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
