<p align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi/main/docs/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A <a href="https://query.farm">Query.Farm</a> VGI worker for DuckDB.</em></p>

# Evaluate Sigma Detection Rules over Log Rows in DuckDB

> **vgi-sigma** · a [Query.Farm](https://query.farm) VGI worker

**Evaluate [Sigma](https://sigmahq.io) detection rules against log/event rows —
detection-as-code, right inside SQL.**

`vgi-sigma` is a [VGI](https://github.com/Query-farm/vgi-python) worker: a Python
process that DuckDB attaches as a catalog and calls like native SQL functions.
Compile a Sigma rule **once**, then test it against every row of a log table:

```sql
INSTALL vgi FROM community; LOAD vgi;
ATTACH 'sigma' (TYPE vgi, LOCATION 'uv run sigma_worker.py');

-- The headline: which log rows match a rule?
SELECT *
FROM windows_security_log AS t
WHERE sigma.sigma_match(
    to_json(t),
    'title: Failed Network Logon
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
    LogonType: 3
  condition: selection');
```

Sigma is the open, vendor-neutral signature format for SIEM detections. This
worker is a **defensive security tool** and completes Query Farm's cyber cluster
alongside `vgi-yara`, `vgi-ioc`, `vgi-cve`, `vgi-pe`, and `vgi-x509`.

---

## Functions

### Scalars (per row)

| Function | Signature | Result |
|----------|-----------|--------|
| `sigma_match` | `(event_json VARCHAR, rule_yaml VARCHAR) → BOOLEAN` | Does the JSON event match the rule? **The headline.** |
| `sigma_check` | `(rule_yaml VARCHAR) → BOOLEAN` | Does the rule parse + compile (with supported features)? |

Scalars take **positional** arguments.

```sql
SELECT sigma.sigma_match('{"EventID": 4625, "LogonType": 3}',
    'logsource: {service: security}
detection: {sel: {EventID: 4625, LogonType: 3}, condition: sel}');         -- true

SELECT sigma.sigma_check(
    'logsource: {service: security}
detection: {sel: {EventID: 1}, condition: sel}');                          -- true
SELECT sigma.sigma_check(': not valid yaml :');                            -- false
```

### Table functions

| Function | Signature | Rows |
|----------|-----------|------|
| `sigma_rule_info` | `(rule_yaml VARCHAR)` | One row: `title, id, level, status, description, product, service, tags VARCHAR[]` |
| `sigma_match_fields` | `(rule_yaml VARCHAR)` | One row per event field the rule references (`field VARCHAR`) |

```sql
SELECT title, level, status FROM sigma.sigma_rule_info('<rule yaml>');
SELECT UNNEST(tags) AS tag FROM sigma.sigma_rule_info('<rule yaml>');
SELECT field FROM sigma.sigma_match_fields('<rule yaml>');  -- index / coverage planning
```

---

## The event-as-JSON contract

`sigma_match` takes the event as a **JSON object string** whose keys are the
field names the rule references. In practice you produce it with DuckDB's
`to_json(t)` over a row (or build it yourself):

```sql
SELECT sigma.sigma_match(to_json(t), :rule) FROM events AS t;
```

- **Field names must match the rule's** (`EventID`, `LogonType`, `CommandLine`, …).
- **Nested fields** are addressed with **dotted** keys in the rule
  (`process.name` → `event["process"]["name"]`); a literal dotted key in the
  event object is also honoured. This matches pySigma's own dotted convention.
- A **missing** field never satisfies a positive comparison.
- An event value that is a JSON **list** matches if **any** element matches.
- A malformed event JSON is treated as a **non-match** (`false`) — one bad log
  row never aborts a column scan. A NULL event or NULL rule yields NULL.

> Every valid Sigma rule must carry a non-empty `logsource:` block (this is a
> Sigma requirement enforced by pySigma). A rule without one fails `sigma_check`
> and raises a clear parse error from the other functions.

---

## Supported Sigma features

The evaluator walks pySigma's parsed **condition tree**, so condition logic is
handled comprehensively, while value matching covers the common modifier set.

**Conditions** (all supported — pySigma expands selectors into the tree):

- `and`, `or`, `not`, and parentheses
- `1 of selection*`, `all of selection*`, `1 of them`, `all of them`
- keyword (fieldless) search terms — matched against every value in the event

**Field modifiers** (supported):

| Modifier | Meaning |
|----------|---------|
| *(none)* | Case-insensitive equality; `*`/`?` wildcards globbed |
| `contains` | Case-insensitive substring |
| `startswith` | Case-insensitive prefix |
| `endswith` | Case-insensitive suffix |
| `re` | Regular expression (Python `re.search`) |
| `all` | Every listed value must match (instead of the default OR) |
| *(list value)* | OR — any one of the listed values matches |

Numbers and booleans compare by value (with sensible string coercion when the
event stringifies them); `field: null` matches an absent or null field.

**Not supported** (a rule using these compiles to `false` in `sigma_check` and
raises a *clear* error from `sigma_match` / the table functions — we never
silently mis-evaluate):

`base64` / `base64offset`, `cidr`, numeric comparisons `lt`/`lte`/`gt`/`gte`,
`utf16`/`wide`, field references (`fieldref`), `|expand` placeholders, and
correlation rules. This is a documented, intentional scope: common
detection-as-code matching, not the full pySigma backend surface.

---

## How it performs

VGI keeps the worker alive across queries, and parsing/compiling a rule is the
expensive step. `sigma_match` compiles each distinct rule **once** (`lru_cache`
keyed by rule text) and then evaluates the cheap condition tree per row — so a
constant rule applied across a million-row log column pays the parse cost a
single time.

---

## Development

```bash
uv sync --extra dev
uv run pytest -q                 # unit + integration
make test-sql                    # end-to-end SQL (haybarn-unittest)
uv run ruff check . && uv run mypy vgi_sigma/
```

`make test-sql` points `VGI_SIGMA_WORKER` at the worker run as a uv stdio
subprocess (exactly how DuckDB drives it after `ATTACH`) and runs the
sqllogictest files under `test/sql/`. Install the runner once with
`uv tool install haybarn-unittest`.

---

## License

`vgi-sigma` is licensed under the **MIT License** — see [LICENSE](LICENSE).

It depends on **[pySigma](https://github.com/SigmaHQ/pySigma)** (the official
`sigma` Python package), which is licensed under the **GNU Lesser General Public
License v2.1 (LGPL-2.1)**. pySigma is used **unmodified** as an ordinary
installed dependency (imported, never altered or statically linked into a
derivative). This worker's own source remains MIT-licensed; redistributing it
together with pySigma must honour pySigma's LGPL-2.1 terms for that component.

---

## Authorship & License

Written by [Query.Farm](https://query.farm).

Copyright 2026 Query Farm LLC - https://query.farm

