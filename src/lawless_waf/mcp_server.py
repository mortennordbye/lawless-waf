"""MCP server: the WAF analysis API as native tools for an AI agent.

Same framework-agnostic :mod:`service` layer the FastAPI app uses — so an agent can run the
whole tuning loop (detect blocks → find the cause → confirm the false positive → write the
exclusion → verify it) by calling tools directly instead of curling the REST API.

Runs over stdio inside the app container (it has the dataset cache at ``$DATA_DIR`` and the
operator's mounted ``az`` session). Wire it into Claude Code with::

    claude mcp add lawless-waf -- docker compose exec -T api python -m lawless_waf.mcp_server

Inputs that cross into SQL/Azure are validated here against the same patterns as the REST
boundary — MCP bypasses FastAPI's query validation, so this is the trust boundary now.
"""

from __future__ import annotations

import functools
import re

from mcp.server.fastmcp import FastMCP

from . import activity, appconfig, service
from .cache import DatasetCache, Scope
from .models import (
    ACTION_PATTERN,
    DATASET_ID_PATTERN,
    DATE_PATTERN,
    IP_PATTERN,
    MATCH_VARIABLE_PATTERN,
    MAX_TF_CONTENT,
    POLICY_PATTERN,
    RULE_ID_PATTERN,
    SEARCH_PATTERN,
    TRACKING_REF_PATTERN,
)
from .settings import get_settings

INSTRUCTIONS = """\
Azure WAF false-positive tuning. Typical loop:
1. refresh_live(date, hour) for live troubleshooting (pulls only new blobs), or download() / \
list_datasets() to pick a window.
2. scanner_report() FIRST — never write an exclusion for a scanner IP.
3. blocks_by_cause() — rules blocking real (non-scanner) traffic. If 0 blocks, the policy may be \
in Detection mode; use summary() + firing_rules() instead.
4. exclusion_context(rule_id) — per match variable it returns a classification \
(false_positive = exclude; not_excludable / attack / scanner_noise = leave it). Confirm with \
rule_events() / request_detail().
5. You write the exclusion in waf-exclusions.tf from terraform.match_variable + selector + \
suggested_operator. Then coverage(tf_content) to check the 100-exclusion budget and avoid dupes.
6. After applying, verify with firing_diff()/rule_diff() — "resolved": true means it stopped firing.
Most tools take a dataset_id plus optional datasets=[...] (span several days) and policy=... (one \
WAF policy)."""

mcp = FastMCP("lawless-waf", instructions=INSTRUCTIONS)


# Mirror every tool call into the shared activity log so the web UI can show what the agent is
# doing live (see lawless_waf.activity). We wrap mcp.tool once here, so the @mcp.tool() decorators
# below each register a logging wrapper without needing to know about it. functools.wraps keeps
# the original signature/docstring, so FastMCP still derives the correct tool schema.
_register_tool = mcp.tool


def _logged_tool(*dargs, **dkwargs):
    register = _register_tool(*dargs, **dkwargs)

    def wrap(fn):
        @functools.wraps(fn)
        def inner(*a, **k):
            try:
                result = fn(*a, **k)
            except Exception as exc:  # record the failure, then let it propagate
                activity.record(fn.__name__, k, error=str(exc))
                raise
            activity.record(fn.__name__, k, result=result)
            return result

        return register(inner)

    return wrap


mcp.tool = _logged_tool


def _cache() -> DatasetCache:
    return DatasetCache(get_settings().data_dir)


def _check(pattern: str, value: str, name: str) -> str:
    if not re.fullmatch(pattern, value):
        raise ValueError(f"invalid {name}: {value!r}")
    return value


def _check_tf(tf_content: str) -> str:
    """The REST boundary caps a pasted waf-exclusions.tf via its request model; this boundary
    has to do it itself."""
    if len(tf_content) > MAX_TF_CONTENT:
        raise ValueError(f"tf_content too large: {len(tf_content)} chars (max {MAX_TF_CONTENT})")
    return tf_content


def _scope(dataset_id: str, datasets: list[str] | None, policy: str | None) -> Scope:
    """Resolve one-or-more dataset ids (+ optional policy) to a Scope; every id must exist."""
    _check(DATASET_ID_PATTERN, dataset_id, "dataset_id")
    for d in datasets or []:
        _check(DATASET_ID_PATTERN, d, "dataset")
    if policy:
        _check(POLICY_PATTERN, policy, "policy")
    cache = _cache()
    ids = list(dict.fromkeys([dataset_id, *(datasets or [])]))
    resolved = []
    for i in ids:
        ds = cache.get(i)
        if not ds.exists:
            raise ValueError(f"dataset {i} not found — download() or refresh_live() it first")
        resolved.append(ds)
    return Scope(tuple(resolved), policy or None)


# ---- datasets / live ----------------------------------------------------------------------

@mcp.tool()
def list_datasets() -> dict:
    """List the WAF datasets already downloaded and ready to analyze."""
    return service.list_datasets(_cache())


@mcp.tool()
def refresh_live(date: str, hour: int) -> dict:
    """Live tail one UTC hour: pull only the newly-arrived blobs (cheap) and return the dataset
    (dataset_id, line_count). Call repeatedly while troubleshooting to follow the current hour.
    date is YYYY-MM-DD (UTC); hour is 0-23 (UTC)."""
    _check(DATE_PATTERN, date, "date")
    if not 0 <= hour <= 23:
        raise ValueError("hour must be 0-23")
    s = get_settings()
    cfg = appconfig.to_azure_config(appconfig.load_target(s))
    return service.ensure_dataset(_cache(), cfg, date, hour, force=False, offline=s.offline, incremental=True)


@mcp.tool()
def download(date: str, hour: int | None = None) -> dict:
    """Download a full UTC day (hour=None) or one UTC hour of WAF logs for analysis. Reuses any
    already-cached window. Use refresh_live() instead for live tailing of the current hour."""
    _check(DATE_PATTERN, date, "date")
    if hour is not None and not 0 <= hour <= 23:
        raise ValueError("hour must be 0-23")
    s = get_settings()
    cfg = appconfig.to_azure_config(appconfig.load_target(s))
    return service.ensure_dataset(_cache(), cfg, date, hour, force=False, offline=s.offline)


# ---- overview / detection -----------------------------------------------------------------

@mcp.tool()
def summary(dataset_id: str, datasets: list[str] | None = None, policy: str | None = None) -> dict:
    """Dataset overview: action mix (Block/AnomalyScoring/Log), cardinalities, policy modes,
    top hosts/IPs, and an activity timeline. Check policy_modes — a Detection-mode policy only
    scores/logs and never blocks."""
    return service.summary(_scope(dataset_id, datasets, policy))


@mcp.tool()
def firing_rules(dataset_id: str, datasets: list[str] | None = None, policy: str | None = None) -> dict:
    """Every rule that fired, by action and volume. AnomalyScoring rows score a request; a Block
    happens only when the combined score crosses the policy threshold."""
    return service.firing_rules(_scope(dataset_id, datasets, policy))


@mcp.tool()
def scanner_report(dataset_id: str, datasets: list[str] | None = None, policy: str | None = None) -> dict:
    """READ FIRST. Segments blocked client IPs into scanners (broad, hostile) vs false-positive
    candidates. Never write an exclusion for a scanner IP."""
    return service.scanner_report(_scope(dataset_id, datasets, policy))


@mcp.tool()
def blocks_by_cause(
    dataset_id: str,
    exclude_scanners: bool = True,
    ip: str | None = None,
    datasets: list[str] | None = None,
    policy: str | None = None,
) -> dict:
    """Rules that block real (non-scanner) traffic — the false-positive worklist. Optionally
    filter to one client ip."""
    if ip:
        _check(IP_PATTERN, ip, "ip")
    return service.blocks_by_cause(_scope(dataset_id, datasets, policy), exclude_scanners=exclude_scanners, ip=ip)


# ---- drill / confirm ----------------------------------------------------------------------

@mcp.tool()
def search(
    dataset_id: str,
    q: str,
    limit: int = 100,
    datasets: list[str] | None = None,
    policy: str | None = None,
) -> dict:
    """Free-text drill: every event whose URI / client IP / host contains q, across all rules and
    actions (the KQL replacement for 'show me everything touching this IP/URL'). limit 1-500."""
    _check(SEARCH_PATTERN, q, "q")
    return service.search_events(_scope(dataset_id, datasets, policy), q, limit=max(1, min(limit, 500)))


@mcp.tool()
def events_by_action(
    dataset_id: str,
    action: str | None = None,
    limit: int = 200,
    datasets: list[str] | None = None,
    policy: str | None = None,
) -> dict:
    """Row-level events for one action (Block / AnomalyScoring / Log), or all when action is None.
    'Block' = what was actually denied. limit 1-500."""
    if action is not None:
        _check(ACTION_PATTERN, action, "action")
    return service.action_events(_scope(dataset_id, datasets, policy), action=action, limit=max(1, min(limit, 500)))


@mcp.tool()
def rule_events(
    dataset_id: str,
    rule_id: str,
    match_variable: str | None = None,
    exclude_scanners: bool = True,
    limit: int = 50,
    datasets: list[str] | None = None,
    policy: str | None = None,
) -> dict:
    """The actual requests a rule matched (URI / IP / host / matched value) — use to confirm a
    false positive before excluding it. Optionally filter to one match_variable. limit 1-500."""
    _check(RULE_ID_PATTERN, rule_id, "rule_id")
    if match_variable is not None:
        _check(MATCH_VARIABLE_PATTERN, match_variable, "match_variable")
    return service.rule_events(
        _scope(dataset_id, datasets, policy), rule_id,
        match_variable=match_variable, exclude_scanners=exclude_scanners, limit=max(1, min(limit, 500)),
    )


@mcp.tool()
def request_detail(
    dataset_id: str,
    tracking_reference: str,
    datasets: list[str] | None = None,
    policy: str | None = None,
) -> dict:
    """Everything the WAF logged for one request: all rules it tripped, matched values, and the
    parsed anomaly score. tracking_reference comes from search/rule_events rows."""
    _check(TRACKING_REF_PATTERN, tracking_reference, "tracking_reference")
    return service.request_detail(_scope(dataset_id, datasets, policy), tracking_reference)


# ---- exclusion context / fix / verify -----------------------------------------------------

@mcp.tool()
def exclusion_context(
    dataset_id: str,
    rule_id: str,
    match_variable: str | None = None,
    datasets: list[str] | None = None,
    policy: str | None = None,
) -> dict:
    """The deliverable for writing an exclusion. Per match variable: a classification
    (false_positive / not_excludable / attack / scanner_noise), evidence, and the
    terraform.match_variable + selector + suggested_operator to put in waf-exclusions.tf."""
    _check(RULE_ID_PATTERN, rule_id, "rule_id")
    if match_variable is not None:
        _check(MATCH_VARIABLE_PATTERN, match_variable, "match_variable")
    return service.exclusion_context(_scope(dataset_id, datasets, policy), rule_id, match_variable=match_variable)


@mcp.tool()
def coverage(
    dataset_id: str,
    tf_content: str,
    datasets: list[str] | None = None,
    policy: str | None = None,
) -> dict:
    """Check your waf-exclusions.tf against what's firing: returns covered rules,
    uncovered_candidates (the real work left), duplicates/conflicts/stale entries, and the
    100-exclusion budget. Pass the file's full text as tf_content."""
    return service.exclusion_coverage(_scope(dataset_id, datasets, policy), _check_tf(tf_content))


@mcp.tool()
def exclusions_count(tf_content: str) -> dict:
    """Slot budget for your waf-exclusions.tf: how many of Azure's 100 exclusion slots it uses,
    the breakdown by match_variable, and consolidation_hints — selectors sharing a prefix that
    could collapse into one StartsWith slot. Use when the budget is tight; no dataset needed."""
    return service.exclusions_count(_check_tf(tf_content))


@mcp.tool()
def firing_diff(
    dataset_id: str,
    against: str,
    datasets: list[str] | None = None,
    policy: str | None = None,
) -> dict:
    """Compare firing rules between two windows (before/after a fix). dataset_id is 'before',
    against is 'after'. status 'resolved' means a rule stopped firing."""
    scope = _scope(dataset_id, datasets, policy)
    after = _scope(_check(DATASET_ID_PATTERN, against, "against"), None, policy)
    return service.diff_firing(scope, after)


@mcp.tool()
def rule_diff(
    dataset_id: str,
    rule_id: str,
    against: str,
    match_variable: str | None = None,
    datasets: list[str] | None = None,
    policy: str | None = None,
) -> dict:
    """Per-match-variable before/after for one rule across two windows — confirm an exclusion
    resolved it. dataset_id is 'before', against is 'after'."""
    _check(RULE_ID_PATTERN, rule_id, "rule_id")
    if match_variable is not None:
        _check(MATCH_VARIABLE_PATTERN, match_variable, "match_variable")
    scope = _scope(dataset_id, datasets, policy)
    after = _scope(_check(DATASET_ID_PATTERN, against, "against"), None, policy)
    return service.diff_rule(scope, after, rule_id, match_variable=match_variable)


if __name__ == "__main__":
    mcp.run()
