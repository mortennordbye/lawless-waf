"""Thin DuckDB execution layer.

Every query runs against a ``logs`` view whose columns are the canonical, WAF-type-agnostic
set defined in :mod:`.schema`. The view projects one or more merged NDJSON files (bound via
``read_json_auto``) — Front Door *or* Application Gateway — onto those columns, so the SQL in
:mod:`.queries` never needs to know which WAF produced the data. File paths are always
server-resolved cache paths (never raw user input); rule/IP filters are bound parameters — no
string concatenation of user input.

The view is the single place that scopes *which rows* an analysis sees: pass several paths to
analyze multiple days together, and/or a ``policy`` to restrict to one WAF policy. Every query
then inherits the scope (and the schema normalization) without changing its own SQL.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import duckdb

from . import schema


def _source_literal(source: Path | list[Path]) -> str:
    """A ``read_json_auto`` source: one quoted path, or a list literal of paths."""
    paths = [source] if isinstance(source, Path) else list(source)
    if not paths:
        raise ValueError("no source paths to query")
    quoted = ", ".join(f"'{str(p).replace(chr(39), chr(39) * 2)}'" for p in paths)
    return f"[{quoted}]" if len(paths) > 1 else quoted


def run(
    source: Path | list[Path],
    sql: str,
    params: list[Any] | None = None,
    *,
    policy: str | None = None,
) -> list[dict[str, Any]]:
    """Bind ``source`` to a canonical ``logs`` view, run ``sql`` against it, return dict rows.

    The WAF type is detected from the data (see :func:`schema.detect_waf_type`) and drives the
    projection, so the same ``sql`` works for Front Door and Application Gateway alike.

    ``CREATE VIEW`` cannot take a prepared parameter, so paths (and the optional policy) are
    interpolated as SQL string literals. Paths are server-resolved cache paths; the policy is
    boundary-validated against ``POLICY_PATTERN``; single quotes are escaped defensively
    regardless.
    """
    src = _source_literal(source)
    projection = schema.canonical_select(src, schema.detect_waf_type(source))
    where = ""
    if policy is not None:
        where = f" WHERE policy = '{policy.replace(chr(39), chr(39) * 2)}'"
    con = duckdb.connect()
    try:
        con.execute(f"CREATE VIEW logs AS SELECT * FROM ({projection}) _canon{where}")  # noqa: S608 — see above
        cur = con.execute(sql, params or [])
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]
    finally:
        con.close()
