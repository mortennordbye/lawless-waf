"""WAF analysis queries — the runbook's DuckDB steps, parametrized and UNNEST-aware.

All queries run against the canonical ``logs`` view (see :mod:`.engine` and :mod:`.schema`),
whose columns are WAF-type-agnostic: ``time``, ``action`` (``Block`` / ``AnomalyScoring`` /
``Log``), ``rule_name`` / ``rule_id`` / ``rule_group``, ``client_ip``, ``request_uri``,
``host``, ``policy`` / ``policy_mode``, ``tracking_reference``, ``msg``, ``data``, and
``matches`` (a ``LIST(STRUCT(varname, varvalue))`` of the matched variables). Front Door and
Application Gateway records are both projected onto these, so the SQL below never references a
raw provider field.

Every function takes ``source`` (one merged path, or a list of them to analyze several days
together) and an optional ``policy`` — both are applied by the engine when it builds the
``logs`` view, so the SQL here never needs to know the scope.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import engine

Source = Path | list[Path]

SAMPLE_LEN = 120  # runbook truncates samples; keep enough for classification.


ACTIONS = "('Block', 'AnomalyScoring', 'Log')"


def summary(source: Source, policy: str | None = None, bucket_len: int = 15) -> dict[str, Any]:
    """Dataset overview for the Analyze dashboard: action mix, cardinalities, top hosts/IPs,
    policy modes, and an activity timeline split by action.

    ``bucket_len`` is the timeline granularity: 15 = 10-minute buckets (single window),
    13 = hourly buckets (multi-day spans, to keep the bar count sane).
    """
    actions = engine.run(
        source,
        f"SELECT action, COUNT(*) AS n FROM logs WHERE action IN {ACTIONS} GROUP BY ALL",
        policy=policy,
    )
    totals = engine.run(
        source,
        f"""
        SELECT COUNT(DISTINCT client_ip) AS distinct_client_ips,
               COUNT(DISTINCT rule_name) AS distinct_rules,
               COUNT(DISTINCT host) AS distinct_hosts
        FROM logs WHERE action IN {ACTIONS}
        """,
        policy=policy,
    )[0]
    top_hosts = engine.run(
        source,
        f"""
        SELECT host, COUNT(*) AS n
        FROM logs WHERE action IN {ACTIONS} AND host IS NOT NULL
        GROUP BY ALL ORDER BY n DESC LIMIT 8
        """,
        policy=policy,
    )
    timeline = engine.run(
        source,
        f"""
        SELECT substr(CAST(time AS VARCHAR), 1, {bucket_len}) AS bucket,
               COUNT(*) FILTER (WHERE action = 'Block') AS block,
               COUNT(*) FILTER (WHERE action = 'AnomalyScoring') AS anomaly,
               COUNT(*) FILTER (WHERE action = 'Log') AS log
        FROM logs WHERE action IN {ACTIONS}
        GROUP BY ALL ORDER BY bucket
        """,
        policy=policy,
    )
    # policy_mode explains the action mix: a Detection-mode policy only scores/logs and never
    # Blocks, so "0 blocks" is expected rather than a bug. policy names which WAF policy fired.
    policy_modes = engine.run(
        source,
        f"SELECT policy_mode AS mode, COUNT(*) AS n FROM logs "
        f"WHERE action IN {ACTIONS} GROUP BY ALL ORDER BY n DESC",
        policy=policy,
    )
    policies = engine.run(
        source,
        f"SELECT policy, COUNT(*) AS n FROM logs "
        f"WHERE action IN {ACTIONS} AND policy IS NOT NULL GROUP BY ALL ORDER BY n DESC",
        policy=policy,
    )
    top_ips = engine.run(
        source,
        f"""
        SELECT client_ip, COUNT(*) AS n,
               COUNT(*) FILTER (WHERE action = 'Block') AS blocks
        FROM logs WHERE action IN {ACTIONS} AND client_ip IS NOT NULL
        GROUP BY ALL ORDER BY n DESC LIMIT 8
        """,
        policy=policy,
    )
    return {
        "actions": {r["action"]: r["n"] for r in actions},
        "distinct_client_ips": totals["distinct_client_ips"],
        "distinct_rules": totals["distinct_rules"],
        "distinct_hosts": totals["distinct_hosts"],
        "policy_modes": policy_modes,
        "policies": policies,
        "top_hosts": top_hosts,
        "top_ips": top_ips,
        "timeline": timeline,
    }


def distinct_policies(source: Source) -> list[str]:
    """Every WAF policy present in the source (for the scope selector)."""
    rows = engine.run(
        source,
        "SELECT DISTINCT policy FROM logs WHERE policy IS NOT NULL ORDER BY policy",
    )
    return [r["policy"] for r in rows]


def firing_rules(source: Source, policy: str | None = None) -> list[dict[str, Any]]:
    """Runbook Step 1: every firing rule by action and volume."""
    sql = """
    SELECT action,
           rule_name,
           rule_group,
           rule_id,
           COUNT(*) AS total
    FROM logs
    WHERE action IN ('Block', 'AnomalyScoring', 'Log')
    GROUP BY ALL
    ORDER BY action, total DESC
    """
    return engine.run(source, sql, policy=policy)


def blocks_by_cause(
    source: Source,
    exclude_ips: list[str] | None = None,
    ip: str | None = None,
    policy: str | None = None,
) -> list[dict[str, Any]]:
    """Runbook Step 2: join Block rows to the AnomalyScoring rules that scored them."""
    sql = """
    WITH blocks AS (
        SELECT tracking_reference AS tr, client_ip AS ip
        FROM logs WHERE action = 'Block'
    ),
    scored AS (
        SELECT tracking_reference AS tr, rule_name, rule_group, rule_id, msg
        FROM logs WHERE action = 'AnomalyScoring'
    )
    SELECT s.rule_name AS rule_name,
           s.rule_group AS rule_group,
           s.rule_id AS rule_id,
           s.msg AS msg,
           COUNT(*) AS hits,
           COUNT(DISTINCT b.ip) AS distinct_ips
    FROM blocks b JOIN scored s ON b.tr = s.tr
    WHERE (b.ip IS NULL OR NOT list_contains(?::VARCHAR[], b.ip))
      AND (? IS NULL OR b.ip = ?)
    GROUP BY ALL
    ORDER BY hits DESC
    """
    return engine.run(source, sql, [exclude_ips or [], ip, ip], policy=policy)


def rule_drill(
    source: Source,
    rule_id: str,
    exclude_ips: list[str] | None = None,
    limit: int = 15,
    policy: str | None = None,
) -> list[dict[str, Any]]:
    """Runbook Steps 3/5: per matched variable, sample values + hits + affected URIs.

    UNNESTs ``matches`` (Front Door rows carry 1–3 matched variables; Application Gateway rows
    carry one parsed from the CRS message; some rows carry none).
    """
    sql = f"""
    WITH scored AS (
        SELECT client_ip AS ip,
               request_uri AS uri,
               UNNEST(matches) AS m
        FROM logs
        WHERE action = 'AnomalyScoring'
          AND rule_id = ?
          AND (client_ip IS NULL OR NOT list_contains(?::VARCHAR[], client_ip))
    )
    SELECT m.varname AS match_variable_name,
           COUNT(*) AS hits,
           COUNT(DISTINCT ip) AS distinct_ips,
           list(DISTINCT left(m.varvalue, {SAMPLE_LEN}))[1:5] AS sample_values,
           list(DISTINCT uri)[1:5] AS affected_uris
    FROM scored
    GROUP BY ALL
    ORDER BY hits DESC
    LIMIT ?
    """
    return engine.run(source, sql, [rule_id, exclude_ips or [], limit], policy=policy)


def rule_events(
    source: Source,
    rule_id: str,
    match_variable: str | None = None,
    exclude_ips: list[str] | None = None,
    limit: int = 50,
    policy: str | None = None,
) -> list[dict[str, Any]]:
    """Row-level drill: individual requests a rule matched, with URI / IP / host / value.

    This is the KQL-replacement view — the actual events behind a rule, so you can confirm a
    false positive before whitelisting it. ``varvalue`` is truncated (it may carry
    tokens/PII). Optionally filter to one matched-variable name.
    """
    sql = f"""
    WITH e AS (
        SELECT time,
               client_ip,
               host,
               request_uri,
               action,
               policy_mode,
               msg,
               tracking_reference,
               UNNEST(matches) AS m
        FROM logs
        WHERE rule_id = ?
          AND (client_ip IS NULL OR NOT list_contains(?::VARCHAR[], client_ip))
    )
    SELECT time, client_ip, host, request_uri, action, policy_mode, msg, tracking_reference,
           m.varname AS match_variable_name,
           left(m.varvalue, {2 * SAMPLE_LEN}) AS match_value
    FROM e
    WHERE (? IS NULL OR m.varname = ?)
    ORDER BY time DESC
    LIMIT ?
    """
    return engine.run(
        source, sql, [rule_id, exclude_ips or [], match_variable, match_variable, limit], policy=policy
    )


def search_events(
    source: Source,
    q: str,
    limit: int = 100,
    policy: str | None = None,
    action: str | None = None,
) -> list[dict[str, Any]]:
    """Free-text drill: every event whose URI, client IP, or host contains ``q``.

    Row-level (no UNNEST) — one row per WAF log record. The KQL-replacement for "show me
    everything touching this IP / URL", regardless of which rule fired. ``q`` is bound as a
    parameter (no injection); ``%``/``_`` in it act as ILIKE wildcards.
    Optional ``action`` narrows results to a single WAF action (e.g. ``"Block"``).
    """
    sql = f"""
    SELECT time,
           client_ip,
           host,
           request_uri,
           action,
           policy_mode,
           msg,
           rule_group,
           rule_id,
           tracking_reference
    FROM logs
    WHERE action IN {ACTIONS}
      AND (? IS NULL OR action = ?)
      AND (request_uri ILIKE '%' || ? || '%'
           OR client_ip ILIKE '%' || ? || '%'
           OR host ILIKE '%' || ? || '%')
    ORDER BY time DESC
    LIMIT ?
    """
    return engine.run(source, sql, [action, action, q, q, q, limit], policy=policy)


def action_events(
    source: Source, action: str | None = None, limit: int = 200, policy: str | None = None
) -> list[dict[str, Any]]:
    """Row-level events for one WAF action (``Block`` / ``AnomalyScoring`` / ``Log``).

    The drill behind the Overview stat tiles: "show me what was blocked / scored / logged".
    Row-level (no UNNEST) — one row per WAF log record, same shape as :func:`search_events`
    so the frontend reuses its table. ``action=None`` returns all firing actions (the "Total
    events" tile). Click a row's trackingReference for the full request.
    """
    sql = f"""
    SELECT time,
           client_ip,
           host,
           request_uri,
           action,
           policy_mode,
           msg,
           rule_group,
           rule_id,
           tracking_reference
    FROM logs
    WHERE action IN {ACTIONS}
      AND (? IS NULL OR action = ?)
    ORDER BY time DESC
    LIMIT ?
    """
    return engine.run(source, sql, [action, action, limit], policy=policy)


def request_detail(source: Source, tracking_reference: str, policy: str | None = None) -> list[dict[str, Any]]:
    """Every WAF log row for one ``tracking_reference`` — the whole offending request.

    One row per rule that fired on the request (each with its matched variables flattened),
    so you see the full picture: which rules, which matched values, host/URI/IP, and the
    blocking-evaluation message that carries the anomaly score. Match values are truncated.
    """
    sql = f"""
    SELECT time,
           client_ip,
           host,
           request_uri,
           action,
           policy,
           policy_mode,
           rule_name,
           rule_group,
           rule_id,
           msg,
           data,
           coalesce(list_transform(matches, x -> x.varname), []::VARCHAR[]) AS match_variable_names,
           coalesce(
               list_transform(matches, x -> left(x.varvalue, {2 * SAMPLE_LEN})),
               []::VARCHAR[]
           ) AS match_values
    FROM logs
    WHERE tracking_reference = ?
    ORDER BY action, rule_id
    """
    return engine.run(source, sql, [tracking_reference], policy=policy)


def block_events(source: Source, policy: str | None = None) -> list[dict[str, Any]]:
    """One row per distinct blocked request, with the client IP — input to scanner
    segmentation. Joined to the scoring rules/URIs that caused each block."""
    sql = """
    WITH blocks AS (
        SELECT DISTINCT tracking_reference AS tr, client_ip AS ip
        FROM logs WHERE action = 'Block'
    ),
    scored AS (
        SELECT tracking_reference AS tr, rule_group, rule_id, request_uri AS uri
        FROM logs WHERE action = 'AnomalyScoring'
    )
    SELECT b.ip AS ip,
           b.tr AS tracking_reference,
           list(DISTINCT s.rule_group) AS rule_groups,
           list(DISTINCT s.rule_id) AS rule_ids,
           any_value(s.uri) AS uri
    FROM blocks b LEFT JOIN scored s ON b.tr = s.tr
    GROUP BY ALL
    """
    return engine.run(source, sql, policy=policy)
