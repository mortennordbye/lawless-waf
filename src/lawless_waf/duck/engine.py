"""Thin DuckDB execution layer.

Every query runs against a ``logs`` view bound to one or more merged NDJSON files via
``read_json_auto``. File paths are always server-resolved cache paths (never raw user
input); rule/IP filters are bound parameters — no string concatenation of user input.

The view is the single place that scopes *which rows* an analysis sees: pass several
paths to analyze multiple days together, and/or a ``policy`` to restrict to one Front
Door policy. Every query then inherits the scope without changing its own SQL.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import duckdb


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
    """Bind ``source`` to a ``logs`` view, run ``sql`` against it, return dict rows.

    ``CREATE VIEW`` cannot take a prepared parameter, so paths (and the optional policy)
    are interpolated as SQL string literals. Paths are server-resolved cache paths; the
    policy is boundary-validated against ``POLICY_PATTERN``; single quotes are escaped
    defensively regardless.
    """
    src = _source_literal(source)
    where = ""
    if policy is not None:
        where = f" WHERE properties.policy = '{policy.replace(chr(39), chr(39) * 2)}'"
    con = duckdb.connect()
    try:
        con.execute(f"CREATE VIEW logs AS SELECT * FROM read_json_auto({src}){where}")  # noqa: S608 — see above
        cur = con.execute(sql, params or [])
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]
    finally:
        con.close()
