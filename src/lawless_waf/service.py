"""Framework-agnostic orchestration: queries + analysis -> plain dicts.

The FastAPI layer (and a future MCP adapter) call these functions; all WAF logic lives
here so there is no duplication across transports.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from collections.abc import Iterator
from datetime import date as date_cls
from datetime import timedelta
from pathlib import Path

from .analysis import classify, exclusions, mapping, scanner
from .azure import downloader, estimate
from .azure.discovery import AzureCliError
from .azure.downloader import AzureConfig
from .cache import Dataset, DatasetCache, Scope
from .duck import queries
from .settings import get_settings

log = logging.getLogger("lawless_waf")


class OfflineError(RuntimeError):
    """Raised when a real Azure download is requested while OFFLINE=true."""


class DownloadInProgress(RuntimeError):
    """Raised when a download for the same day/hour is already running."""


def _dataset_meta(ds: Dataset, cached: bool) -> dict:
    return {
        "dataset_id": ds.id,
        "date": ds.date,
        "hour": ds.hour,
        "line_count": ds.line_count,
        "merged_path": str(ds.merged_path),
        "cached": cached,
    }


def list_datasets(cache: DatasetCache) -> dict:
    return {"datasets": [_dataset_meta(ds, cached=True) for ds in cache.list()]}


def delete_dataset(cache: DatasetCache, ds_id: str) -> dict:
    return {"dataset_id": ds_id, "deleted": cache.delete(ds_id)}


def clear_datasets(cache: DatasetCache) -> dict:
    return {"deleted": cache.clear()}


def ensure_dataset(
    cache: DatasetCache,
    cfg: AzureConfig,
    date: str,
    hour: int | None,
    force: bool,
    offline: bool,
    incremental: bool = False,
) -> dict:
    """Make a day/hour available locally, downloading from Azure only when needed.

    ``force`` re-pulls every blob (overwrite). ``incremental`` (live tailing) re-checks Azure
    but downloads *without* overwrite, so ``download-batch`` skips blobs already on disk and
    fetches only the new 5-minute windows that have appeared — then re-merges. This is the
    cheap path: it tails the growing hour instead of re-downloading the whole pile each tick.
    """
    ds = cache.resolve(date, hour)
    if ds.exists and not force and not incremental:
        return _dataset_meta(ds, cached=True)
    if offline:
        raise OfflineError("OFFLINE=true: refusing to download; seed the dataset instead.")

    try:
        fd = cache.acquire_lock(date, hour)
    except FileExistsError as e:
        raise DownloadInProgress(f"download already in progress for {ds.id}") from e
    lock = cache.lock_path(date, hour)
    try:
        os.close(fd)
        if incremental:
            _download_incremental(cfg, date, hour, cache.raw_dir(date, hour), ds.merged_path)
        else:
            downloader.download(
                cfg, date, hour, cache.raw_dir(date, hour), ds.merged_path, overwrite=force
            )
        return _dataset_meta(cache.resolve(date, hour), cached=False)
    finally:
        lock.unlink(missing_ok=True)


def _download_incremental(cfg: AzureConfig, date: str, hour: int | None, raw_dir: Path, merged_path: Path) -> None:
    """Tail an hour by fetching only the blobs not already on disk, plus re-pulling the latest
    (still-being-written) window — then re-merge. Cheap per tick: usually 0–1 new small blobs."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    base = estimate.discover_base_prefix(cfg)
    names = sorted(estimate.day_blob_names(cfg, base, date, hour))
    latest = names[-1] if names else None
    for name in names:
        dest = raw_dir / name
        if name == latest:
            # The current window is an append blob Front Door is still writing. Pulling it can
            # fail (e.g. 412 ConditionNotMet: its ETag changed mid-download) — that's expected
            # when tailing a live blob, so it's best-effort: skip it this tick and merge what we
            # have. The next tick re-pulls it. Any prior copy of the window stays in place.
            try:
                downloader.download_blob(cfg, name, dest)
            except AzureCliError as e:
                log.warning("live tail: latest window unavailable this tick, retrying next: %s", e)
        elif not dest.exists():
            # Older windows are immutable once present, so only fetch the ones we're missing.
            downloader.download_blob(cfg, name, dest)
    downloader.merge_blobs(raw_dir, merged_path)


def _count_raw_blobs(raw_dir: Path) -> int:
    """How many blob files have landed so far — the live downloaded count for the bar."""
    try:
        return sum(1 for _ in raw_dir.rglob("PT5M.json"))
    except OSError:
        return 0


def _discover_blob_count(cfg: AzureConfig, date: str, hour: int | None) -> int | None:
    """Best-effort total blob count for the progress bar's denominator (None = unknown)."""
    try:
        base = estimate.discover_base_prefix(cfg)
        return estimate.day_bytes(cfg, base, date, hour)[1]
    except Exception:  # noqa: BLE001 — a missing total just degrades to an indeterminate bar
        return None


def stream_dataset(
    cache: DatasetCache,
    cfg: AzureConfig,
    date: str,
    hour: int | None,
    force: bool,
    offline: bool,
    total: int | None = None,
) -> Iterator[dict]:
    """Download a day/hour, yielding live blob-level progress for the UI's progress bar.

    Same effect as :func:`ensure_dataset`, but as a generator of progress events so the
    frontend can show how much is left. The ``az download-batch`` runs in a worker thread
    while we poll the raw dir for the file count; ``total`` (from the estimate the UI already
    has) is the denominator, discovered on the server only if not supplied.

    Events: ``{"phase": "cached"|"listing"|"start"|"progress"|"done"|"error", ...}``. The
    stream always ends with exactly one terminal ``done`` (carries the dataset meta) or
    ``error`` event.
    """
    ds = cache.resolve(date, hour)
    if ds.exists and not force:
        yield {"phase": "cached", "dataset": _dataset_meta(ds, cached=True)}
        return
    if offline:
        yield {"phase": "error", "detail": "OFFLINE=true: refusing to download; seed the dataset instead."}
        return

    try:
        fd = cache.acquire_lock(date, hour)
    except FileExistsError:
        yield {"phase": "error", "detail": f"download already in progress for {ds.id}"}
        return
    lock = cache.lock_path(date, hour)
    os.close(fd)

    raw_dir = cache.raw_dir(date, hour)
    try:
        if total is None:
            yield {"phase": "listing"}
            total = _discover_blob_count(cfg, date, hour)

        result: dict = {}

        def worker() -> None:
            try:
                downloader.download(cfg, date, hour, raw_dir, ds.merged_path, overwrite=force)
            except Exception as e:  # noqa: BLE001 — surfaced to the client as an error event
                result["error"] = e

        worker_thread = threading.Thread(target=worker, daemon=True)
        worker_thread.start()
        yield {"phase": "start", "total": total}
        while worker_thread.is_alive():
            yield {"phase": "progress", "downloaded": _count_raw_blobs(raw_dir), "total": total}
            worker_thread.join(timeout=0.5)

        if "error" in result:
            # downloader.download already raises AzureCliError with an actionable message.
            detail = str(result["error"]) or "download failed"
            yield {"phase": "error", "detail": detail}
            return

        meta = _dataset_meta(cache.resolve(date, hour), cached=False)
        final = total if total is not None else _count_raw_blobs(raw_dir)
        yield {"phase": "progress", "downloaded": final, "total": total}
        yield {"phase": "done", "dataset": meta}
    finally:
        lock.unlink(missing_ok=True)


MAX_RANGE_DAYS = 92


def _expand_dates(date_from: str, date_to: str) -> list[str]:
    """Inclusive list of YYYY-MM-DD between the two dates. Raises ValueError if invalid."""
    start, end = date_cls.fromisoformat(date_from), date_cls.fromisoformat(date_to)
    if end < start:
        raise ValueError("date_to is before date_from")
    if (end - start).days + 1 > MAX_RANGE_DAYS:
        raise ValueError(f"range exceeds {MAX_RANGE_DAYS} days")
    return [(start + timedelta(days=i)).isoformat() for i in range((end - start).days + 1)]


def estimate_range(
    cache: DatasetCache,
    cfg: AzureConfig,
    date_from: str,
    date_to: str,
    hour: int | None,
    offline: bool,
    blobs_per_sec: float,
) -> dict:
    """Estimate download size + ETA for a date range. Cached days are reported as free.

    ETA is driven by blob count (per-blob overhead dominates), not bytes.
    """
    dates = _expand_dates(date_from, date_to)
    if offline:
        raise OfflineError("OFFLINE=true: cannot estimate; estimates need a live Azure session.")

    base: str | None = None  # discovered lazily — skipped entirely if everything is cached
    days, dl_bytes, dl_blobs, cached_days, on_disk = [], 0, 0, 0, 0
    for d in dates:
        ds = cache.resolve(d, hour)
        if ds.exists:
            size = ds.merged_path.stat().st_size  # real on-disk size, no Azure call
            cached_days += 1
            on_disk += size
            days.append({"date": d, "bytes": size, "blob_count": 0, "cached": True})
        else:
            if base is None:
                base = estimate.discover_base_prefix(cfg)
            b, n = estimate.day_bytes(cfg, base, d, hour)
            dl_bytes += b
            dl_blobs += n
            on_disk += b
            days.append({"date": d, "bytes": b, "blob_count": n, "cached": False})

    seconds = round(dl_blobs / blobs_per_sec, 1) if blobs_per_sec > 0 and dl_blobs else 0.0
    return {
        "days": days,
        "cached_days": cached_days,
        "download_bytes": dl_bytes,
        "download_blob_count": dl_blobs,
        "on_disk_bytes": on_disk,
        "estimated_seconds": seconds,
        "blobs_per_sec": blobs_per_sec,
    }


def speedtest(cfg: AzureConfig, offline: bool) -> dict:
    """Measure the real download rate against Azure (opt-in; downloads one hour)."""
    if offline:
        raise OfflineError("OFFLINE=true: cannot run a speedtest without a live Azure session.")
    return estimate.measure_rate(cfg)


def _scanner_ips(scope: Scope) -> list[str]:
    return scanner.build_report(queries.block_events(scope.source, policy=scope.policy)).scanner_ips


def _scope_meta(scope: Scope) -> dict:
    return {
        "dataset_id": scope.id,
        "dataset_ids": scope.dataset_ids,
        "policy": scope.policy,
    }


def list_policies(scope: Scope) -> dict:
    """Every WAF policy present (unfiltered) — drives the scope selector."""
    return {"dataset_id": scope.id, "policies": queries.distinct_policies(scope.source)}


def summary(scope: Scope) -> dict:
    # Hourly buckets for multi-day spans, 10-minute buckets for a single window.
    bucket_len = 13 if scope.spans_multiple_days else 15
    return {**_scope_meta(scope), **queries.summary(scope.source, policy=scope.policy, bucket_len=bucket_len)}


def firing_rules(scope: Scope) -> dict:
    return {**_scope_meta(scope), "rules": queries.firing_rules(scope.source, policy=scope.policy)}


def scanner_report(scope: Scope) -> dict:
    report = scanner.build_report(queries.block_events(scope.source, policy=scope.policy))
    return {**_scope_meta(scope), **report.to_dict()}


def blocks_by_cause(scope: Scope, exclude_scanners: bool = True, ip: str | None = None) -> dict:
    exclude = _scanner_ips(scope) if exclude_scanners else []
    return {
        **_scope_meta(scope),
        "exclude_scanners": exclude_scanners,
        "excluded_ips": exclude,
        "rules": queries.blocks_by_cause(scope.source, exclude_ips=exclude, ip=ip, policy=scope.policy),
    }


def rule_drill(scope: Scope, rule_id: str, exclude_scanners: bool = True, limit: int = 15) -> dict:
    exclude = _scanner_ips(scope) if exclude_scanners else []
    return {
        **_scope_meta(scope),
        "rule_id": rule_id,
        "exclude_scanners": exclude_scanners,
        "matches": queries.rule_drill(
            scope.source, rule_id, exclude_ips=exclude, limit=limit, policy=scope.policy
        ),
    }


def rule_events(
    scope: Scope,
    rule_id: str,
    match_variable: str | None = None,
    exclude_scanners: bool = True,
    limit: int = 50,
) -> dict:
    """Row-level requests behind a rule — the deepest drill (replaces ad-hoc KQL)."""
    exclude = _scanner_ips(scope) if exclude_scanners else []
    return {
        **_scope_meta(scope),
        "rule_id": rule_id,
        "match_variable": match_variable,
        "events": queries.rule_events(
            scope.source, rule_id, match_variable=match_variable, exclude_ips=exclude,
            limit=limit, policy=scope.policy,
        ),
    }


def search_events(scope: Scope, q: str, limit: int = 100, action: str | None = None) -> dict:
    """Free-text event search across the scope (by IP / URI / host substring)."""
    return {
        **_scope_meta(scope),
        "query": q,
        "events": queries.search_events(scope.source, q, limit=limit, policy=scope.policy, action=action),
    }


def action_events(scope: Scope, action: str | None = None, limit: int = 200) -> dict:
    """Events for one action — the drill behind the Overview Blocked/Scored/Logged tiles."""
    return {
        **_scope_meta(scope),
        "action": action,
        "events": queries.action_events(scope.source, action, limit=limit, policy=scope.policy),
    }


# CRS records the combined anomaly score in the blocking-evaluation message, e.g.
# "Inbound Anomaly Score Exceeded (Total Score: 5)". Only read it from anomaly-score
# messages so a number elsewhere (a URL, matched data) can't masquerade as the score.
_SCORE_RE = re.compile(r"score[^0-9]{0,40}(\d{1,4})", re.I)


def _parse_anomaly_score(rows: list[dict]) -> int | None:
    scores = [
        int(m.group(1))
        for r in rows
        if (msg := (r.get("msg") or "")) and "anomaly" in msg.lower()
        for m in [_SCORE_RE.search(msg)]
        if m
    ]
    return max(scores) if scores else None


def request_detail(scope: Scope, tracking_reference: str) -> dict:
    """Everything the WAF logged for one request: all rules + matched vars + anomaly score."""
    rows = queries.request_detail(scope.source, tracking_reference, policy=scope.policy)
    return {
        **_scope_meta(scope),
        "tracking_reference": tracking_reference,
        "anomaly_score": _parse_anomaly_score(rows),
        "rows": rows,
    }


def _diff_status(before: int, after: int) -> str:
    if before > 0 and after == 0:
        return "resolved"
    if before == 0 and after > 0:
        return "new"
    if after < before:
        return "reduced"
    if after > before:
        return "increased"
    return "unchanged"


def diff_firing(before: Scope, after: Scope) -> dict:
    """What changed between two windows: every rule's volume before vs after (e.g. to
    confirm an exclusion took effect, or spot a new rule that started firing)."""

    def totals(scope: Scope) -> dict[str, dict]:
        agg: dict[str, dict] = {}
        for r in queries.firing_rules(scope.source, policy=scope.policy):
            row = agg.setdefault(r["rule_id"], {"rule_group": r["rule_group"], "total": 0})
            row["total"] += r["total"]
        return agg

    b, a = totals(before), totals(after)
    rules = []
    for rid in b.keys() | a.keys():
        bt = b.get(rid, {}).get("total", 0)
        at = a.get(rid, {}).get("total", 0)
        rules.append(
            {
                "rule_id": rid,
                "rule_group": (a.get(rid) or b.get(rid))["rule_group"],
                "before": bt,
                "after": at,
                "delta": at - bt,
                "status": _diff_status(bt, at),
            }
        )
    rules.sort(key=lambda r: (-abs(r["delta"]), r["rule_id"]))
    return {
        "before_id": before.id,
        "after_id": after.id,
        "policy": before.policy,
        "rules": rules,
    }


def diff_rule(before: Scope, after: Scope, rule_id: str, match_variable: str | None = None) -> dict:
    """Per-match-variable before/after for one rule — did this exclusion candidate stop firing?"""

    def drill(scope: Scope) -> dict[str, dict]:
        return {
            r["match_variable_name"]: r
            for r in queries.rule_drill(scope.source, rule_id, limit=100, policy=scope.policy)
        }

    b, a = drill(before), drill(after)
    items = []
    for mv in sorted(b.keys() | a.keys()):
        if match_variable and mv != match_variable:
            continue
        bh = b.get(mv, {}).get("hits", 0)
        ah = a.get(mv, {}).get("hits", 0)
        items.append(
            {
                "match_variable_name": mv,
                "before_hits": bh,
                "after_hits": ah,
                "delta": ah - bh,
                "status": _diff_status(bh, ah),
            }
        )
    before_hits = sum(i["before_hits"] for i in items)
    after_hits = sum(i["after_hits"] for i in items)
    return {
        "before_id": before.id,
        "after_id": after.id,
        "rule_id": rule_id,
        "before_hits": before_hits,
        "after_hits": after_hits,
        "resolved": before_hits > 0 and after_hits == 0,
        "match_variables": items,
    }


def _build_exclusion_context(scope: Scope, rule_id: str, match_variable: str | None = None) -> dict:
    trusted = get_settings().trusted_domain_list
    scanner_ips = _scanner_ips(scope)
    all_rows = {
        r["match_variable_name"]: r
        for r in queries.rule_drill(scope.source, rule_id, limit=100, policy=scope.policy)
    }
    ns_rows = {
        r["match_variable_name"]: r
        for r in queries.rule_drill(
            scope.source, rule_id, exclude_ips=scanner_ips, limit=100, policy=scope.policy
        )
    }
    rule_group = next(
        (
            r["rule_group"]
            for r in queries.firing_rules(scope.source, policy=scope.policy)
            if r["rule_id"] == rule_id
        ),
        None,
    )
    items: list[dict] = []
    for mv_name, row in all_rows.items():
        if match_variable and mv_name != match_variable:
            continue
        ns = ns_rows.get(mv_name)
        ns_hits = ns["hits"] if ns else 0
        total_hits = row["hits"]
        samples = (ns or row)["sample_values"]
        m = mapping.map_match_variable(mv_name)

        if not m.excludable:
            classification, evidence = "not_excludable", []
        elif ns_hits == 0:
            classification, evidence = "scanner_noise", []
        else:
            classification, evidence = classify.classify_samples(samples, trusted)

        items.append(
            {
                "match_variable_name": mv_name,
                "terraform": (
                    {"match_variable": m.match_variable, "selector": m.selector}
                    if m.excludable
                    else None
                ),
                "not_excludable_reason": m.reason if not m.excludable else None,
                "suggested_operator": "Equals",
                "classification": classification,
                "evidence": evidence,
                "hit_count": total_hits,
                "non_scanner_hits": ns_hits,
                "scanner_share": round(1 - ns_hits / total_hits, 3) if total_hits else None,
                "distinct_ips": (ns or row)["distinct_ips"],
                "sample_values": samples,
                "affected_uris": (ns or row)["affected_uris"],
            }
        )
    return {"rule_group": rule_group, "contexts": items}


def exclusion_context(scope: Scope, rule_id: str, match_variable: str | None = None) -> dict:
    """The deliverable: structured exclusion context Claude Code turns into Terraform."""
    ctx = _build_exclusion_context(scope, rule_id, match_variable)
    return {**_scope_meta(scope), "rule_id": rule_id, **ctx}


# Cap how many firing rules coverage cross-references (each one runs a drill).
COVERAGE_RULE_LIMIT = 40


def exclusion_coverage(scope: Scope, tf_text: str) -> dict:
    """Cross-reference the existing waf-exclusions.tf against what's firing now.

    Tells you which firing rules are already covered (so you don't redo them), which
    excludable false-positive candidates are still uncovered (the real work left), plus
    duplicate / conflicting / apparently-stale exclusions.
    """
    parsed = exclusions.parse_exclusions(tf_text)

    # Duplicates (same mv+selector+operator) and conflicts (same mv+selector, different op).
    seen_full: set[tuple] = set()
    seen_pair: dict[tuple, str] = {}
    duplicates, conflicts = [], []
    for e in parsed:
        pair = (e["match_variable"], e["selector"])
        full = (*pair, e["operator"])
        if full in seen_full:
            duplicates.append(e)
        elif pair in seen_pair:
            conflicts.append({**e, "conflicts_with_operator": seen_pair[pair]})
        seen_full.add(full)
        seen_pair.setdefault(pair, e["operator"])

    firing = queries.firing_rules(scope.source, policy=scope.policy)
    rule_ids = list(dict.fromkeys(r["rule_id"] for r in firing if r["action"] == "AnomalyScoring"))
    truncated = len(rule_ids) > COVERAGE_RULE_LIMIT
    rule_ids = rule_ids[:COVERAGE_RULE_LIMIT]

    matched_exclusions: set[int] = set()
    rules_out, uncovered = [], []
    for rid in rule_ids:
        ctx = _build_exclusion_context(scope, rid)
        for item in ctx["contexts"]:
            tf = item["terraform"]
            covering = None
            if tf and tf["selector"]:
                for idx, e in enumerate(parsed):
                    if e["match_variable"] == tf["match_variable"] and exclusions.selector_matches(
                        e, tf["selector"]
                    ):
                        covering = e
                        matched_exclusions.add(idx)
                        break
            row = {
                "rule_id": rid,
                "rule_group": ctx["rule_group"],
                "match_variable_name": item["match_variable_name"],
                "classification": item["classification"],
                "terraform": tf,
                "hit_count": item["hit_count"],
                "covered_by": covering,
            }
            rules_out.append(row)
            if tf and covering is None and item["classification"] in {"false_positive", "mixed", "unknown"}:
                uncovered.append(row)

    stale = [e for idx, e in enumerate(parsed) if idx not in matched_exclusions]
    return {
        **_scope_meta(scope),
        "total_exclusions": len(parsed),
        "limit": exclusions.LIMIT,
        "remaining": exclusions.LIMIT - len(parsed),
        "rules_checked": len(rule_ids),
        "truncated": truncated,
        "coverage": rules_out,
        "uncovered_candidates": uncovered,
        "duplicates": duplicates,
        "conflicts": conflicts,
        "stale_exclusions": stale,
    }


def exclusions_count(tf_text: str) -> dict:
    return exclusions.count_exclusions(tf_text)
