# Sigma examples

[01 · Condition matches still need source scope](01_condition_matches_need_source_scope.ipynb)
uses twelve authored records to distinguish valid event objects, missing fields,
raw condition matches and matches selected for a declared log source. It also
checks evaluator capabilities before accepting a rule: the modifier reference
supports plain numeric equality, while an unsupported `base64` rewrite is rejected.
The two SVG charts retain every input record and explain what a false result hides.

[Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-sigma/blob/main/notebooks/01_condition_matches_need_source_scope.ipynb),
run the install cell, then **Run all**. The rule and all event rows are visible SQL
inside the notebook; no clone, fixture download or private ruleset is required.
The base shared package preserves compatible Colab plotting/data libraries.
Hosted Colab itself has not been tested; a fresh Python 3.12 notebook-only run with
preloaded libraries is validated separately.

For a local run, install Python 3.11+ and [uv](https://docs.astral.sh/uv/), then:

```sh
cd notebooks
uv sync --locked --extra runner
uv run --locked --extra runner vgi-notebooks
```

The optional `runner` extra installs the local execution kernel. For an interactive
kernel use `uv run --locked --extra runner python -m ipykernel install --user
--name vgi-sigma-notebooks --display-name 'VGI Sigma notebooks'`; select it in
Jupyter, restart and run all after changing a parameter.

The visible SQL launches the published release in a separate worker environment:

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'sigma' (TYPE vgi,
  LOCATION 'uvx --python 3.14 --from git+https://github.com/Query-farm/vgi-sigma@v0.4.0 vgi-sigma-worker');
```

The shared package supplies `uvx`; it retrieves Python 3.14 and the release's own
published dependencies on first use. No local worker checkout or dependency
overrides are needed. The tested release environment resolved vgi-python 0.51.1,
vgi-rpc 0.53.1, pyArrow 26.0.1 and pySigma 2.1.0; these versions are recorded in
coverage provenance. Parsing and evaluation are local after installation. The
notebook is validated on macOS Apple silicon using Haybarn 2.0.0rc11. A disposable
empty SQL-secret directory and disabled persistent secrets isolate the session;
cleanup closes the database and worker.

Change one policy parameter to include condition matches whose source labels do
not establish the rule's declared scope:

```sh
uv run --locked --extra runner vgi-notebooks \
  --parameters '{"ENFORCE_LOGSOURCE": false}' \
  --output-dir validation/unscoped
```

The selected population rises from two to four; raw condition matches and the
field-availability grid stay unchanged. `wrong-source` and `unknown-source` have
the same matching JSON payload as the two in-scope fixtures. This comparison does
not authenticate labels, fix malformed events, or measure detection accuracy.
Reset `ENFORCE_LOGSOURCE=True` for the saved default.

The shared [standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.2/docs/standard.md)
and runner are pinned at **v0.3.2**, without duplicated presentation/runner files.
Native SVG outputs also have content-addressed `charts/` assets for GitHub;
experiment copies keep native SVG. Keep historical chart assets when updating an
example. The runner preserves the saved default on failure and requires a separate
destination for parameter overrides.

[Coverage evidence](coverage.json) records **five of five public SQL surfaces** for
release v0.4.0 and the reviewed current-public revision: four functions and the
`supported_modifiers` view. `coverage/` contains complete function, table and view
catalog exports, hash-bound execution receipts and explicit narrative reviews.
Current-source catalog discovery is separate from the release used by the notebook;
metadata-only source differences do not add public surfaces. No hard or
credential-dependent objects are excluded.

The original `fixtures/events.jsonl`, manifest and deterministic builder are retained
as provenance. The notebook's inline records match them exactly. Rebuild those
archived files with `uv run --locked python fixtures/build.py`. All data is synthetic;
source labels are authored annotations and no real account or machine log is used.

The evaluator applies the condition tree, without routing by `logsource`; SQL makes
source policy explicit. Malformed/non-object JSON returns false, while SQL NULL
returns NULL. The field grid is specific to flat fields in a positive-AND rule;
OR, NOT, null comparisons and nested paths need different coverage interpretation.
A rule match or declared severity is not an incident verdict.
