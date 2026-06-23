# CLAUDE.md — vgi-sigma

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion.

## What this is

A [VGI](https://query.farm) worker that evaluates [Sigma](https://sigmahq.io)
detection rules ("detection-as-code") against log/event rows, as DuckDB scalar
and table functions, backed by [pySigma](https://github.com/SigmaHQ/pySigma)
(the official `sigma` package; **LGPL-2.1** — see the license note below). A
defensive security tool, completing Query Farm's cyber cluster (`vgi-yara`,
`vgi-ioc`, `vgi-cve`, `vgi-pe`, `vgi-x509`). `sigma_worker.py` assembles every
function into one `sigma` catalog (single `main` schema) over stdio. Sibling
style/tooling to `vgi-pii` / `vgi-conform`.

## Layout

```
sigma_worker.py    repo-root stdio entry point; PEP 723 inline deps; main()
vgi_sigma/
  engine.py        pure parse + compile + evaluate; lru_cache by rule text; no Arrow/VGI; unit-testable
  scalars.py       per-row scalars: sigma_match, sigma_check
  tables.py        table functions: sigma_rule_info, sigma_match_fields
  schema_utils.py  pa.Field comment / column-doc helper
tests/             pytest: test_engine (pure), test_tables (in-proc), test_scalars (Client RPC)
test/sql/*.test    haybarn-unittest sqllogictest — authoritative E2E
Makefile           test / test-unit / test-sql / lint
```

To add a function: implement the logic in `engine.py` (pure; total for events —
never raises on a garbage event row; raises a *clear* error for a bad rule), wrap
it as a scalar or table function in the matching module, register it in
`sigma_worker.py`'s catalog list.

## How evaluation works — the key design choice

pySigma already parses a rule into a boolean **condition tree** via
`rule.detection.parsed_condition[0].parse()`: `ConditionAND` / `ConditionOR` /
`ConditionNOT` (each with `.args`) over leaf nodes. **We evaluate that tree
directly** rather than re-implementing condition parsing. Crucially, the selector
forms (`1 of selection_*`, `all of them`, `all of selection_*`, …) are *expanded
by pySigma into the same tree*, so they work for free.

Two leaf kinds:
- `ConditionFieldEqualsValueExpression` — `.field` vs `.value`. The parsed leaf
  drops the modifier, so we recover the comparison kind (contains/startswith/…)
  from the originating `SigmaDetectionItem` via `node.parent.modifiers`.
- `ConditionValueExpression` — a bare keyword, matched against every value
  anywhere in the event.

Value types we handle: `SigmaString` (with `*`/`?` wildcards → regex),
`SigmaNumber`, `SigmaBool`, `SigmaNull`, `SigmaRegularExpression`.

## Scalars vs table functions — core convention

- **Per-row functions are scalars, positional-only** (`name := value` is rejected
  for scalars). `sigma_match(event_json, rule_yaml)` and `sigma_check(rule_yaml)`.
- **Introspection functions are table functions** (`sigma_rule_info`,
  `sigma_match_fields`). `sigma_rule_info`'s **`tags` column is a `VARCHAR[]`** —
  declared in the `FIXED_SCHEMA` as `pa.list_(pa.string())`.
- The expensive parse/compile is wrapped in `engine.compile_rule` (`lru_cache`,
  keyed by rule text): a constant rule over a log column compiles **once**,
  evaluates per row. This is the whole performance story.

## Sharp edges (learned the hard way)

1. **Every Sigma rule MUST have a non-empty `logsource:` block.** pySigma raises
   `SigmaLogsourceError` otherwise. All example rules (in docstrings, README,
   tests, SQL) include one; a rule without it fails `sigma_check` / raises a clear
   parse error. Don't write `logsource: {}` either — it must be non-empty.

2. **Robustness asymmetry, by design.** A malformed *event* JSON in
   `sigma_match` → `false` (one bad log row must not abort a column scan). A
   malformed/unsupported *rule* → a clear raised error from `sigma_match` /
   table functions, and `false` from `sigma_check`. We never *silently*
   mis-evaluate an unsupported modifier — `compile_rule` validates the modifier
   set up front and raises `UnsupportedRuleError`.

3. **NULL → NULL / no rows**, everywhere (scalars return `None`; table functions
   emit no rows).

4. **SQL `.test` multi-line rules** use DuckDB's `E'...\n...'` escape strings.
   Determinism comes from `rowsort` / `ORDER BY` and the `lru_cache`.

5. **pySigma version drift.** We walk pySigma's internal condition/types classes
   (`sigma.conditions`, `sigma.types`). A major pySigma bump could rename these;
   the `engine.py` imports are the canary. Pinned `pysigma>=0.11`.

## pySigma license note (IMPORTANT)

pySigma is **LGPL-2.1** (verified: `Classifier: License :: OSI Approved :: GNU
Lesser General Public License v2 (LGPLv2)`, version 1.3.3). It is used
**unmodified** as an ordinary installed dependency — imported, never patched or
statically linked into a derivative — exactly as `vgi-conform` treats
`python-stdnum`. This worker's own source stays **MIT**; redistribution
alongside pySigma must honour pySigma's LGPL terms for that component. The note
is mirrored prominently in `README.md`.

## Verify

```sh
export PATH="$HOME/.local/bin:$PATH"; cd ~/Development/vgi-sigma
uv sync --extra dev
uv run --no-sync pytest -q
make test-sql
uv run --no-sync ruff check . && uv run --no-sync mypy vgi_sigma/
```
