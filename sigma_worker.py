# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.8.3",
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

_SIGMA_CATALOG = Catalog(
    name="sigma",
    default_schema="main",
    schemas=[
        Schema(
            name="main",
            comment="Evaluate Sigma detection rules against log/event rows for SQL",
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
