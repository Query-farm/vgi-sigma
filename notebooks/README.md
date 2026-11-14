# VGI Sigma notebooks

[01 · Condition matches still need source scope](01_condition_matches_need_source_scope.ipynb)
uses visible Haybarn SQL to inspect a Sigma rule, audit event JSON and referenced
fields, evaluate the condition, and select matches for its declared log source.
Two charts preserve field availability and reconcile every input to a review state.
The saved notebook is executed against the real worker using synthetic events.

## Run

Install `uv` so both `uv` and `uvx` are on PATH, then from this directory:

```sh
uv sync --locked
uv run --locked python execute.py
```

The whole `notebooks/` directory works when copied elsewhere. No worker checkout is
required. The runner uses this directory as its working directory and a temporary
kernel, replacing the saved notebook only after successful execution. Internet
access is required initially for Python dependencies, the community VGI extension,
and the Git-backed worker environment. Tested on macOS Apple silicon with Python
3.14 and Haybarn 2.0.0rc11; compatible dependency wheels are required.

For VS Code, select this directory's `.venv/bin/python` as the kernel, or register it:

```sh
uv run --locked python -m ipykernel install --user --name vgi-sigma-notebooks --display-name 'Python (vgi-sigma notebooks)'
```

Use this directory as the working directory when running interactively. Parameters,
VGI connection SQL and analytical SQL remain visible; preparation, plots and cleanup
are folded. Restart and run all after changing `ENFORCE_LOGSOURCE`.

## Experiment

```sh
uv run --locked python execute.py --parameters '{"ENFORCE_LOGSOURCE": false}' --output-dir validation/unscoped
```

Overrides require a separate output directory, which receives branding, fixtures and
environment companions. Removing scope gating raises selected matches from two to
four, with no change to raw worker matches or field availability. The wrong-source
and unknown-source fixtures contain the same positive event payload as the two
in-scope records. Reset `True` to restore the default.

## Startup and provenance

The visible literal `ATTACH` uses `uvx --from` at immutable Git commit
`42390f68a4febac437403b2f48ada067f1c6fe23` (release v0.4.0), with worker pins
`vgi-python==0.51.0`, `vgi-rpc==0.53.1`, `pyarrow==26.0.1` and `pysigma==2.0.2`.
These match the tested protocol/parser family; the notebook environment has its own
lockfile. To upgrade, change the visible launcher pin and verify both parameter
settings. No local worker code is imported into the notebook kernel.

`fixtures/events.jsonl` contains twelve authored records with synthetic source labels
and event strings: matching objects, absent/null fields, nonmatching values, an empty
object, a JSON array, malformed JSON, and NULL input. There are no real accounts,
credentials or machine logs. Source labels are fixture annotations, not authenticated
provenance. `fixtures/manifest.json` records the file hash. Regenerate it with:

```sh
uv run --locked python fixtures/build.py
```

The rule source is visible in SQL. Folded preparation quotes that exact source for
constant-argument table calls; `sigma_rule_info` and `sigma_match_fields` still run
through VGI. The latter supplies the field-coverage grid. No private ruleset or
external rule repository is downloaded.

## Interpretation and validation

The worker evaluates the condition tree, without applying the `logsource` metadata
as an event-routing filter. SQL explicitly compares product/service labels. A label
match does not authenticate provenance. The example's completeness grid is specific
to flat fields in a positive-AND rule; OR, NOT, null comparisons and nested fields
need different interpretation.

Malformed and non-object event JSON return false; absent input returns NULL. The
notebook retains those distinctions instead of treating every false result as a
valid negative observation. A rule match or declared severity is not an incident
verdict. The experiment broadens selection scope; it does not measure precision,
recall, prevalence or the quality of the rule.

Default and detached experiment runs pass twelve SQL checks and two chart
reconciliations. Both charts are inspected in both modes. Runner guards cover
missing output directory for overrides, unknown parameters and invalid-parameter
failure preserving saved outputs. Fixture regeneration matches the saved hash.

Repository validation passes 54 pytest tests, Ruff/format, mypy, CI-isolated
pydoclint, and 63/71/63 SQL assertions across subprocess/HTTP/Unix transports (four
cases each). The existing metadata gate exits 2: score 100/100, L0, zero errors,
one VGI417 warning for oversized metadata on `sigma.main`. Structural and behavioral
checks ran; the baseline metadata limitation is unchanged. Worker source and root
manifest/lock files remain unchanged.

Official Query.Farm Strata Sun and VGI assets are bundled unchanged. The wordmark
links to Query.Farm at the notebook's top and final bottom.
