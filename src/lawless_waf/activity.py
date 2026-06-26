"""Append-only MCP activity log, shared via the filesystem between the MCP server and the API.

The MCP server runs as its own process (``docker compose exec api python -m
lawless_waf.mcp_server``) but shares ``$DATA_DIR`` with the FastAPI app. Each MCP tool call is
appended here as one JSON line; the API tails this file over SSE so the web UI can show what the
agent is doing live. Best-effort by design — logging must never break a tool call.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from .settings import get_settings

_MAX_LINES = 1000  # keep the log bounded: once it passes this, rewrite with the most recent _KEEP
_KEEP = 500
_lock = threading.Lock()


def _path() -> Path:
    return Path(get_settings().data_dir) / ".activity.jsonl"


def _truncate(value: str, n: int = 120) -> str:
    return value if len(value) <= n else value[: n - 1] + "…"


def _clean_args(args: dict | None) -> dict:
    """Keep only small scalar args; summarize lists by length. Drops bulky values (e.g. tf_content)."""
    out: dict = {}
    for k, v in (args or {}).items():
        if isinstance(v, bool) or isinstance(v, (int, float)):
            out[k] = v
        elif isinstance(v, str) and v:
            out[k] = _truncate(v)
        elif isinstance(v, (list, tuple)) and v:
            out[k] = f"[{len(v)}]"
    return out


def _summarize(result: object) -> str:
    """A one-line gist of a tool result for the activity feed."""
    try:
        if isinstance(result, dict):
            if "line_count" in result:
                return f"{result['line_count']} lines"
            for key, val in result.items():
                if isinstance(val, list):
                    return f"{len(val)} {key}"
            return "ok"
        if isinstance(result, list):
            return f"{len(result)} items"
        return _truncate(str(result))
    except Exception:
        return "ok"


def record(tool: str, args: dict | None = None, *, result: object = None, error: str | None = None) -> None:
    """Append one activity event. Never raises — logging is best-effort."""
    event = {
        "ts": time.time(),
        "tool": tool,
        "args": _clean_args(args),
        "summary": error if error else _summarize(result),
        "ok": error is None,
    }
    line = json.dumps(event, default=str)
    try:
        with _lock:
            path = _path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            _trim(path)
    except Exception:
        pass  # an unwritable log must not break the tool


def _trim(path: Path) -> None:
    """Once the file passes _MAX_LINES, atomically rewrite it with the last _KEEP events."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    if len(lines) <= _MAX_LINES:
        return
    tmp = path.with_suffix(".jsonl.tmp")
    tmp.write_text("\n".join(lines[-_KEEP:]) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read(after: float = 0.0, limit: int | None = None) -> list[dict]:
    """Events with ts > after, oldest→newest. With limit and after==0, the most recent `limit`."""
    try:
        raw = _path().read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events = []
    for ln in raw:
        ln = ln.strip()
        if not ln:
            continue
        try:
            ev = json.loads(ln)
        except ValueError:
            continue
        if ev.get("ts", 0) > after:
            events.append(ev)
    events.sort(key=lambda e: e.get("ts", 0))
    if limit is not None and after == 0.0:
        return events[-limit:]
    return events
