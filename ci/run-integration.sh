#!/usr/bin/env bash
# Copyright 2026 Query Farm LLC - https://query.farm
#
# Run this repo's sqllogictest suite (test/sql/*.test) against the vgi-sigma
# VGI worker, using a prebuilt standalone `haybarn-unittest` and the signed
# community `vgi` extension — no C++ build from source. See ci/README.md.
#
# The SAME suite is exercised over three VGI transports, selected by $TRANSPORT.
# The vgi extension picks the transport from the LOCATION string the .test files
# ATTACH (`${VGI_SIGMA_WORKER}`):
#
#   subprocess : a bare stdio command (`uv run sigma_worker.py`) — the
#                extension spawns the worker per query and talks Arrow IPC over
#                stdin/stdout. Default; current behavior.
#   http       : the worker is started out-of-band in `--http` mode on an auto
#                port; LOCATION becomes `http://127.0.0.1:<port>`.
#   unix       : the worker is started out-of-band on an AF_UNIX socket;
#                LOCATION becomes `unix://<sock>`.
#
# The sigma worker is offline/compute (it evaluates Sigma rules in-process; no
# network, no fixture files — every rule is inline in the .test files), so no
# mock/fixture server is needed for any transport.
#
# Required environment:
#   HAYBARN_UNITTEST     path to the haybarn-unittest binary
# Optional:
#   TRANSPORT            subprocess | http | unix (default: subprocess)
#   WORKER_CMD           the stdio command that runs the worker. Used directly
#                        as the LOCATION for subprocess, and as the process to
#                        boot the server for http/unix. Defaults to
#                        `uv run --no-sync --python 3.13 <repo>/sigma_worker.py`.
#   STAGE                scratch dir for the preprocessed test tree (default: mktemp)
set -euo pipefail

: "${HAYBARN_UNITTEST:?path to the haybarn-unittest binary}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
STAGE="${STAGE:-$(mktemp -d)}"
TRANSPORT="${TRANSPORT:-subprocess}"
WORKER_CMD="${WORKER_CMD:-uv run --no-sync --python 3.13 $REPO/sigma_worker.py}"

case "$TRANSPORT" in
  subprocess|http|unix) ;;
  *) echo "ERROR: unknown TRANSPORT '$TRANSPORT' (want subprocess|http|unix)" >&2; exit 2 ;;
esac

echo "Staging preprocessed tests into $STAGE ..."
mkdir -p "$STAGE/test/sql"
for f in "$REPO"/test/sql/*.test; do
  awk -f "$HERE/preprocess-require.awk" "$f" > "$STAGE/test/sql/$(basename "$f")"
done

# ---------------------------------------------------------------------------
# Per-transport: resolve VGI_SIGMA_WORKER (the LOCATION) and, for the
# out-of-band transports, boot the worker server + arrange trap-cleanup.
# ---------------------------------------------------------------------------
SERVER_PID=""
SOCK=""
PORT_FILE=""

cleanup() {
  # Preserve the script's exit status: this runs on EXIT, so its own last
  # command must not clobber the real exit code (a bare `[ -n "$x" ]` that is
  # false returns 1 and would turn a green run red under `set -e`).
  local rc=$?
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$SOCK" ]]; then rm -f "$SOCK"; fi
  if [[ -n "$PORT_FILE" ]]; then rm -f "$PORT_FILE"; fi
  return "$rc"
}
trap cleanup EXIT

case "$TRANSPORT" in
  subprocess)
    export VGI_SIGMA_WORKER="$WORKER_CMD"
    echo "Transport: subprocess/stdio — VGI_SIGMA_WORKER=$VGI_SIGMA_WORKER"
    ;;

  http)
    # The vgi extension's HTTP transport is implemented on top of DuckDB's
    # httpfs extension, so an `http://` ATTACH binds with
    #   "Binder Error: VGI HTTP transport requires the httpfs extension."
    # unless httpfs is loaded first. (The haybarn sqllogictest runner's default
    # skip list swallows any error containing "HTTP", so without this the whole
    # suite would silently SKIP rather than fail — a fake pass.) The .test files
    # are transport-agnostic; inject a signed `INSTALL httpfs FROM core; LOAD
    # httpfs;` right after each `LOAD vgi;` in the staged files, so httpfs is
    # present only when we actually run over HTTP.
    echo "Injecting httpfs load into staged tests (HTTP transport needs it) ..."
    for sf in "$STAGE"/test/sql/*.test; do
      awk '
        { print }
        /^LOAD[ \t]+vgi[ \t]*;[ \t]*$/ {
          print "";
          print "statement ok";
          print "INSTALL httpfs FROM core;";
          print "";
          print "statement ok";
          print "LOAD httpfs;";
        }
      ' "$sf" > "$sf.tmp" && mv "$sf.tmp" "$sf"
    done

    # Boot the worker in HTTP mode on an auto-selected port. The worker writes
    # the chosen port to --port-file atomically (tmp + rename), so we watch for
    # the file to appear rather than parsing stdout. HTTP mode needs the `http`
    # extra (waitress); WORKER_CMD resolves it from the PEP 723 header / lock.
    # cwd = STAGE so any relative-path resolution matches the runner's cwd.
    PORT_FILE="$(mktemp -u "${TMPDIR:-/tmp}/sigma-port.XXXXXX")"
    LOG_FILE="${TMPDIR:-/tmp}/sigma-http-server.log"
    echo "Starting HTTP worker: $WORKER_CMD --http --port 0 --port-file $PORT_FILE"
    # shellcheck disable=SC2086
    ( cd "$STAGE" && exec $WORKER_CMD --http --port 0 --port-file "$PORT_FILE" ) > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!

    PORT=""
    for _ in $(seq 1 120); do
      if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: HTTP worker exited before reporting a port. Log:" >&2
        cat "$LOG_FILE" >&2
        exit 1
      fi
      if [[ -s "$PORT_FILE" ]]; then
        PORT="$(tr -d '[:space:]' < "$PORT_FILE")"
        [[ -n "$PORT" ]] && break
      fi
      sleep 0.5
    done
    if [[ -z "$PORT" ]]; then
      echo "ERROR: timed out waiting for HTTP worker port-file. Log:" >&2
      cat "$LOG_FILE" >&2
      exit 1
    fi
    echo "HTTP worker ready on port $PORT (pid $SERVER_PID)"
    # The LOCATION must be the bare scheme://host:port with NO path suffix; the
    # extension POSTs each RPC method at <LOCATION>/<method>.
    export VGI_SIGMA_WORKER="http://127.0.0.1:$PORT"
    ;;

  unix)
    # Boot the worker bound to an AF_UNIX socket. We poll for the socket file to
    # appear (and bail if the process dies). cwd = STAGE as above.
    SOCK="${TMPDIR:-/tmp}/sigma-$$.sock"
    rm -f "$SOCK"
    LOG_FILE="${TMPDIR:-/tmp}/sigma-unix-server.log"
    echo "Starting unix worker: $WORKER_CMD --unix $SOCK"
    # shellcheck disable=SC2086
    ( cd "$STAGE" && exec $WORKER_CMD --unix "$SOCK" ) > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!

    READY=""
    for _ in $(seq 1 120); do
      if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: unix worker exited before binding the socket. Log:" >&2
        cat "$LOG_FILE" >&2
        exit 1
      fi
      if [[ -S "$SOCK" ]]; then
        READY=1
        break
      fi
      sleep 0.5
    done
    if [[ -z "$READY" ]]; then
      echo "ERROR: timed out waiting for unix worker socket. Log:" >&2
      cat "$LOG_FILE" >&2
      exit 1
    fi
    echo "unix worker ready on $SOCK (pid $SERVER_PID)"
    export VGI_SIGMA_WORKER="unix://$SOCK"
    ;;
esac

cd "$STAGE"

# Warm the extension cache once: vgi from the signed community channel. A miss
# here is only a warning — the per-test INSTALL/LOAD (injected by
# preprocess-require.awk) is what actually gates each file.
echo "Warming the extension cache (vgi from community) ..."
mkdir -p "$STAGE/test"
cat > "$STAGE/test/_warm.test" <<'EOF'
# name: test/_warm.test
# group: [warm]
statement ok
INSTALL vgi FROM community;
EOF
"$HAYBARN_UNITTEST" "test/_warm.test" >/dev/null 2>&1 || echo "::warning::extension warm step did not fully succeed"
rm -f "$STAGE/test/_warm.test"

# Run the whole suite in one invocation, capturing the runner's native
# sqllogictest report so we can both stream it AND guard against a silent skip.
#
# IMPORTANT: the DuckDB/Haybarn sqllogictest runner SKIPS (not fails, exit 0) a
# test whose error message matches a built-in network-error allowlist that
# includes the substring "HTTP" / "Unable to connect". So a broken HTTP/unix
# transport would otherwise show "All tests were skipped" and the job would go
# GREEN having run nothing — a fake pass. We detect that and fail explicitly.
echo "Running suite (transport: $TRANSPORT, worker: $VGI_SIGMA_WORKER) ..."
RUN_LOG="$STAGE/run.log"
set +e
"$HAYBARN_UNITTEST" "test/sql/*" 2>&1 | tee "$RUN_LOG"
RUN_RC="${PIPESTATUS[0]}"
set -e

if [ "$RUN_RC" -ne 0 ]; then
  echo "ERROR: suite failed (transport: $TRANSPORT, rc=$RUN_RC)" >&2
  exit "$RUN_RC"
fi

# Guard against the silent-skip fake-pass (see comment above).
if grep -q 'All tests were skipped' "$RUN_LOG"; then
  echo "ERROR: every test was SKIPPED on transport '$TRANSPORT' (the runner's" >&2
  echo "       built-in network-error skip swallowed the real error). This is" >&2
  echo "       NOT a pass. Skip reason reported by the runner:" >&2
  grep -A3 'Skipped tests for the following reasons' "$RUN_LOG" >&2 || true
  exit 1
fi
