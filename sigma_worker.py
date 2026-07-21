# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.16.0",
#     "pysigma>=0.11",
# ]
# ///
"""Repo-root PEP 723 entry point for the vgi-sigma worker.

The worker's catalog, :class:`SigmaWorker`, and :func:`main` now live in the
wheel-importable :mod:`vgi_sigma.worker` module so the published distribution
contains the whole worker. This thin shim re-exports them and stays runnable
verbatim as ``uv run sigma_worker.py`` (used by the Makefile,
``ci/run-integration.sh``, and the pytest subprocess tests), resolving the
inline PEP 723 dependencies above.

    uv run sigma_worker.py               # serve over stdio (DuckDB subprocess)

    INSTALL vgi FROM community; LOAD vgi;
    ATTACH 'sigma' (TYPE vgi, LOCATION 'uv run sigma_worker.py');
"""

from __future__ import annotations

from vgi_sigma.worker import SigmaWorker, main

__all__ = ["SigmaWorker", "main"]


if __name__ == "__main__":
    main()
