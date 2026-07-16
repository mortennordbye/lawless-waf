"""Normalize the two Azure WAF log schemas into one canonical column set.

Azure emits two different WAF firewall-log shapes:

* **Front Door** (``insights-logs-frontdoorwebapplicationfirewalllog``): a request that
  fires rules produces one ``AnomalyScoring`` record per contributing rule plus one
  ``Block`` record (the blocking-evaluation rule ``949110``), all sharing a
  ``trackingReference``. Fields live under ``properties`` — ``clientIP``, ``ruleName``
  (``<ruleset>-<ver>-<GROUP>-<ID>``), ``host``, ``details.matches[]`` (an array of
  ``{matchVariableName, matchVariableValue}``), ``policy``/``policyMode``.

* **Application Gateway** (``insights-logs-applicationgatewayfirewalllog``): the same CRS
  anomaly-scoring model, but flatter — one record per contributing rule with action
  ``Matched`` and a final ``Blocked`` record (rule ``949110``), all sharing a
  ``transactionId``. Fields are ``clientIp`` (lowercase p), separate ``ruleId`` /
  ``ruleGroup`` / ``ruleSetType`` / ``ruleSetVersion``, ``hostname``, and a single matched
  variable encoded as ModSecurity text in ``details.message`` / ``details.data``
  (``... found within ARGS:paramname ...``), plus ``policyId`` and ``policyScope``.

The engine binds a ``logs`` view to :func:`canonical_select`, which projects **either**
schema onto the same flat columns. Every analysis query in :mod:`.queries` then reads those
canonical columns and never needs to know which WAF produced the data. The canonical action
vocabulary is Front Door's — ``Block`` / ``AnomalyScoring`` / ``Log`` — because the whole app
(and its API/MCP contracts) already speaks it; Application Gateway's ``Blocked`` / ``Matched``
/ ``Detected`` map straight onto it.
"""

from __future__ import annotations

import json
from pathlib import Path

FRONT_DOOR = "frontdoor"
APP_GATEWAY = "appgw"
WAF_TYPES = (FRONT_DOOR, APP_GATEWAY)

# Canonical columns the `logs` view always exposes (documented for readers of queries.py):
#   time, action, rule_name, rule_id, rule_group, client_ip, request_uri, host,
#   policy, policy_mode, tracking_reference, msg, data,
#   matches  -- LIST(STRUCT(varname VARCHAR, varvalue VARCHAR))

# Front Door: last "-segment" of ruleName is the id; the group is between "<ver>-" and "-<id>".
_FD_RULE_ID = r"regexp_extract(properties.ruleName, '-([^-]+)$', 1)"
_FD_RULE_GROUP = r"regexp_extract(properties.ruleName, '^.*?-[0-9]+\.[0-9]+-(.*)-[^-]+$', 1)"

_FRONT_DOOR_SELECT = f"""
SELECT
    time,
    properties.action AS action,
    properties.ruleName AS rule_name,
    {_FD_RULE_ID} AS rule_id,
    {_FD_RULE_GROUP} AS rule_group,
    properties.clientIP AS client_ip,
    properties.requestUri AS request_uri,
    properties.host AS host,
    properties.policy AS policy,
    properties.policyMode AS policy_mode,
    properties.trackingReference AS tracking_reference,
    properties.details.msg AS msg,
    properties.details.data AS data,
    coalesce(
        list_transform(
            properties.details.matches,
            m -> struct_pack(varname := m.matchVariableName, varvalue := m.matchVariableValue)
        ),
        []::STRUCT(varname VARCHAR, varvalue VARCHAR)[]
    ) AS matches
FROM read_json_auto({{src}})
"""  # noqa: S608 — trusted schema projection; only constant SQL is interpolated

# Application Gateway encodes the matched variable as ModSecurity text: the CRS collection and
# the argument/header/cookie name appear as "... at REQUEST_HEADERS:Host ..." (the operator
# message) or "... found within ARGS:name ..." (the "Matched Data:" logdata). Pull the first
# "COLLECTION[:name]" token so mapping.py can translate it to an exclusion match_variable +
# selector. The name is optional (a rule can match a whole collection, e.g. "within
# REQUEST_BODY"); when present it is an arg/header/cookie name that must start and end with a
# name char, so a trailing sentence period or a "=value" tail is not swallowed into the selector.
#
# The CRS-generated message fields are searched *before* details.data (the raw matched value,
# which is attacker-influenced): otherwise a value containing "at FOO" / "found within FOO" could
# preempt the real collection. The remaining pathological case (the value carries a fake location
# and no message field does) yields a wrong selector suggestion, not a security issue — the
# classification + human review are the real gate before an exclusion is applied.
# The concatenated CRS text (message fields before the raw value) mv is parsed from — see above.
_APPGW_MV_BLOB = "coalesce(dmsg, '') || ' ' || coalesce(msg1, '') || ' ' || coalesce(ddata, '')"
_APPGW_MV = (
    f"regexp_extract({_APPGW_MV_BLOB}, "
    r"'(?:found\s+within|at)\s+([A-Z_]+(?::[A-Za-z0-9_-](?:[A-Za-z0-9_.-]*[A-Za-z0-9_-])?)?)', 1)"
)

# CRS logs each contributing rule as "Matched" and the blocking decision (rule 949110) as
# "Blocked"; Detection mode uses "Detected". Map onto Front Door's Block/AnomalyScoring/Log so
# the blocks<->scoring join, action filters, and every downstream query work unchanged.
_APPGW_ACTION = """
    CASE act
        WHEN 'Blocked' THEN 'Block'
        WHEN 'Matched' THEN 'AnomalyScoring'
        WHEN 'Detected' THEN 'Log'
        WHEN 'Allowed' THEN 'Log'
        WHEN 'JSChallengeBlock' THEN 'Block'
        WHEN 'JSChallengeIssued' THEN 'Log'
        WHEN 'JSChallengePass' THEN 'Log'
        WHEN 'JSChallengeValid' THEN 'Log'
        ELSE act
    END
"""

# Application Gateway's log schema is variable — policyId, ruleGroup, policyScope and others are
# not always present — and struct field access errors when a field is absent from the whole file.
# So read each field out of the record as JSON (json_extract_string returns NULL for a missing
# key), then derive the canonical columns. Three CTEs: `raw` gets the record as JSON, `f` extracts
# the raw fields, `d` derives the canonical ones (and parses the matched variable `mv` once).
_APP_GATEWAY_SELECT = f"""
WITH raw AS (
    SELECT time, to_json(properties) AS j FROM read_json_auto({{src}})
),
f AS (
    SELECT time,
        json_extract_string(j, '$.action') AS act,
        json_extract_string(j, '$.ruleSetType') AS rst,
        json_extract_string(j, '$.ruleSetVersion') AS rsv,
        json_extract_string(j, '$.ruleGroup') AS rg,
        json_extract_string(j, '$.ruleId') AS rid,
        json_extract_string(j, '$.clientIp') AS cip,
        json_extract_string(j, '$.requestUri') AS ruri,
        json_extract_string(j, '$.hostname') AS hn,
        json_extract_string(j, '$.policyId') AS pid,
        json_extract_string(j, '$.transactionId') AS txid,
        json_extract_string(j, '$.message') AS msg1,
        json_extract_string(j, '$.details.message') AS dmsg,
        json_extract_string(j, '$.details.data') AS ddata
    FROM raw
),
d AS (
    SELECT time,
        {_APPGW_ACTION} AS action,
        concat_ws('-', rst, rsv, rg, rid) AS rule_name,
        rid AS rule_id,
        rg AS rule_group,
        cip AS client_ip,
        ruri AS request_uri,
        hn AS host,
        nullif(regexp_extract(coalesce(pid, ''), '([^/]+)$', 1), '') AS policy,
        CASE WHEN act = 'Detected' THEN 'Detection' ELSE 'Prevention' END AS policy_mode,
        txid AS tracking_reference,
        coalesce(msg1, dmsg) AS msg,
        ddata AS data,
        {_APPGW_MV} AS mv
    FROM f
)
SELECT time, action, rule_name, rule_id, rule_group, client_ip, request_uri, host, policy,
       policy_mode, tracking_reference, msg, data,
       CASE
           WHEN mv = '' THEN []::STRUCT(varname VARCHAR, varvalue VARCHAR)[]
           ELSE [struct_pack(varname := mv, varvalue := coalesce(data, ''))]
       END AS matches
FROM d
"""  # noqa: S608 — trusted schema projection; only constant SQL is interpolated

_SELECTS = {FRONT_DOOR: _FRONT_DOOR_SELECT, APP_GATEWAY: _APP_GATEWAY_SELECT}

# A zero-row relation with the canonical columns, used when every source file is empty (a quiet
# hour / zero blobs writes a present-but-empty merged.json). ``read_json_auto`` over an empty
# file exposes no columns, so projecting ``time``/``action``/... off it would raise a binder
# error; this yields the same empty result the queries expect instead.
EMPTY_SELECT = """
SELECT
    NULL::VARCHAR AS time,
    NULL::VARCHAR AS action,
    NULL::VARCHAR AS rule_name,
    NULL::VARCHAR AS rule_id,
    NULL::VARCHAR AS rule_group,
    NULL::VARCHAR AS client_ip,
    NULL::VARCHAR AS request_uri,
    NULL::VARCHAR AS host,
    NULL::VARCHAR AS policy,
    NULL::VARCHAR AS policy_mode,
    NULL::VARCHAR AS tracking_reference,
    NULL::VARCHAR AS msg,
    NULL::VARCHAR AS data,
    []::STRUCT(varname VARCHAR, varvalue VARCHAR)[] AS matches
WHERE false
"""


def canonical_select(src: str, waf_type: str) -> str:
    """The ``SELECT ... FROM read_json_auto(src)`` that projects ``waf_type`` records onto the
    canonical columns. ``src`` is an already-quoted ``read_json_auto`` source literal."""
    try:
        template = _SELECTS[waf_type]
    except KeyError as e:
        raise ValueError(f"unknown waf_type: {waf_type!r}") from e
    return template.format(src=src).strip()


def has_records(path: Path) -> bool:
    """True if ``path`` has at least one non-blank line (i.e. read_json_auto will see a record).

    An empty or whitespace-only merged.json otherwise makes the canonical projection fail to
    bind (no columns to project); callers substitute :data:`EMPTY_SELECT` when nothing does."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            return any(line.strip() for line in fh)
    except OSError:
        return False


# Cached per path (not per (path, mtime)) so a re-merged dataset replaces its entry instead of
# accumulating one forever — live tailing re-merges the same hour many times.
_detect_cache: dict[str, tuple[float, str]] = {}


def detect_waf_type(source: Path | list[Path]) -> str:
    """Which WAF produced a merged dataset, from its first record. Cached by path (mtime-checked).

    Detection is by field shape rather than the storage namespace, so the projection is always
    correct even if a file lands in the wrong place: Application Gateway records carry
    ``clientIp`` / ``transactionId`` / ``ruleSetType``; Front Door carries ``clientIP`` /
    ``trackingReference`` / ``ruleName``. An empty or unreadable file defaults to Front Door
    (its queries then just return nothing).
    """
    path = source if isinstance(source, Path) else source[0]
    key = str(path)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return FRONT_DOOR
    cached = _detect_cache.get(key)
    if cached is not None and cached[0] == mtime:
        return cached[1]
    waf_type = _detect(path)
    _detect_cache[key] = (mtime, waf_type)
    return waf_type


def _detect(path: Path) -> str:
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    props = json.loads(line).get("properties") or {}
                except (ValueError, AttributeError):
                    continue
                if "clientIp" in props or "transactionId" in props or "ruleSetType" in props:
                    return APP_GATEWAY
                return FRONT_DOOR
    except OSError:
        pass
    return FRONT_DOOR
