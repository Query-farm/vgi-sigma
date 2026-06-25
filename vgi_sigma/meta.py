"""Shared helpers for per-object discovery/description metadata tags.

The ``vgi-lint`` strict profile expects these on **every** function and table.
Each function/table surfaces them in its ``Meta.tags``:

- ``vgi.title`` (VGI124)        -- human-friendly display name (must not
  normalize-equal the machine name; add an extra word).
- ``vgi.doc_llm`` (VGI112)      -- Markdown narrative aimed at LLMs/agents.
- ``vgi.doc_md`` (VGI113)       -- Markdown narrative aimed at human docs
  (must be distinct content from ``vgi.doc_llm``).
- ``vgi.keywords`` (VGI138)     -- search terms/synonyms, serialized as a JSON
  array of strings (e.g. ``["sigma", "detection"]``), not a CSV string.

Note: per-object ``vgi.source_url`` is intentionally *not* set here (VGI139);
``source_url`` belongs only on the catalog object.
"""

from __future__ import annotations

import json


def keywords_json(*keywords: str) -> str:
    """Serialize search keywords as a JSON array of strings (VGI138).

    Args:
        *keywords: Individual search terms/synonyms, one per argument.

    Returns:
        A JSON array string such as ``["sigma", "detection"]``.
    """
    return json.dumps(list(keywords))


def object_tags(
    *,
    title: str,
    doc_llm: str,
    doc_md: str,
    keywords: str,
) -> dict[str, str]:
    """Build the standard per-object discovery/description tags.

    Args:
        title: Human-friendly display name (VGI124).
        doc_llm: Markdown narrative for LLMs/agents (VGI112).
        doc_md: Markdown narrative for human docs (VGI113); distinct from
            ``doc_llm``.
        keywords: Search terms/synonyms as a JSON array string (VGI138); build
            it with :func:`keywords_json`.

    Returns:
        A tag dict ready to merge into a function's ``Meta.tags``.
    """
    return {
        "vgi.title": title,
        "vgi.doc_llm": doc_llm,
        "vgi.doc_md": doc_md,
        "vgi.keywords": keywords,
    }
