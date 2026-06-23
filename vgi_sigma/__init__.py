"""Evaluate Sigma detection rules against log/event rows as a VGI worker.

Sigma (https://sigmahq.io) is the open, vendor-neutral signature format for
SIEM detection rules ("detection-as-code"). This worker brings Sigma matching
*into* SQL: compile a rule once, then test it against every row of a log table.

The implementation is split so each concern stays focused:

- ``engine``  -- the pure parse + compile + evaluate logic (no Arrow / VGI
  dependency, directly unit-testable). A rule YAML is parsed by pySigma into a
  boolean condition tree, validated against the supported modifier set, cached
  by rule text (``lru_cache``), and evaluated against an event ``dict``.
- ``scalars`` -- per-row VGI scalar functions: ``sigma_match`` (the headline --
  does this event match this rule?) and ``sigma_check`` (does the rule parse?).
- ``tables``  -- set-returning functions: ``sigma_rule_info`` (one metadata row)
  and ``sigma_match_fields`` (the fields the rule references).

``sigma_worker.py`` at the repo root assembles these into the ``sigma`` catalog
and runs the worker over stdio (or HTTP).
"""

from __future__ import annotations

__version__ = "0.1.0"
