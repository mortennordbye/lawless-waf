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
# the argument/header/cookie name appear as "... found within ARGS:name ..." (in details.data)
# or "... at REQUEST_HEADERS:Host ..." (in details.message). Pull the first "COLLECTION[:name]"
# token so mapping.py can translate it to an exclusion match_variable + selector. The name is
# optional (a rule can match a whole collection, e.g. "within REQUEST_BODY") and, when present,
# stops at the next colon/space/comma (values follow a second colon, e.g. "ARGS:name: value").
_APPGW_MATCH_VAR = (
    "regexp_extract("
    "coalesce(properties.details.data, '') || ' ' "
    "|| coalesce(properties.details.message, '') || ' ' "
    "|| coalesce(properties.message, ''), "
    r"'(?:within|at)\s+([A-Z_]+(?::[^\s,:]+)?)', 1)"
)

# CRS logs each contributing rule as "Matched" and the blocking decision (rule 949110) as
# "Blocked"; Detection mode uses "Detected". Map onto Front Door's Block/AnomalyScoring/Log so
# the blocks<->scoring join, action filters, and every downstream query work unchanged.
_APPGW_ACTION = """
    CASE properties.action
        WHEN 'Blocked' THEN 'Block'
        WHEN 'Matched' THEN 'AnomalyScoring'
        WHEN 'Detected' THEN 'Log'
        WHEN 'Allowed' THEN 'Log'
        WHEN 'JSChallengeBlock' THEN 'Block'
        WHEN 'JSChallengeIssued' THEN 'Log'
        WHEN 'JSChallengePass' THEN 'Log'
        WHEN 'JSChallengeValid' THEN 'Log'
        ELSE properties.action
    END
"""

_APP_GATEWAY_SELECT = f"""
SELECT
    time,
    {_APPGW_ACTION} AS action,
    concat_ws('-', properties.ruleSetType, CAST(properties.ruleSetVersion AS VARCHAR),
              properties.ruleGroup, CAST(properties.ruleId AS VARCHAR)) AS rule_name,
    CAST(properties.ruleId AS VARCHAR) AS rule_id,
    properties.ruleGroup AS rule_group,
    properties.clientIp AS client_ip,
    properties.requestUri AS request_uri,
    properties.hostname AS host,
    regexp_extract(coalesce(CAST(properties.policyId AS VARCHAR), ''), '([^/]+)$', 1) AS policy,
    CASE WHEN properties.action = 'Detected' THEN 'Detection' ELSE 'Prevention' END AS policy_mode,
    CAST(properties.transactionId AS VARCHAR) AS tracking_reference,
    coalesce(properties.message, properties.details.message) AS msg,
    properties.details.data AS data,
    CASE
        WHEN {_APPGW_MATCH_VAR} = '' THEN []::STRUCT(varname VARCHAR, varvalue VARCHAR)[]
        ELSE [struct_pack(
            varname := {_APPGW_MATCH_VAR},
            varvalue := coalesce(CAST(properties.details.data AS VARCHAR), '')
        )]
    END AS matches
FROM read_json_auto({{src}})
"""  # noqa: S608 — trusted schema projection; only constant SQL is interpolated

_SELECTS = {FRONT_DOOR: _FRONT_DOOR_SELECT, APP_GATEWAY: _APP_GATEWAY_SELECT}


def canonical_select(src: str, waf_type: str) -> str:
    """The ``SELECT ... FROM read_json_auto(src)`` that projects ``waf_type`` records onto the
    canonical columns. ``src`` is an already-quoted ``read_json_auto`` source literal."""
    try:
        template = _SELECTS[waf_type]
    except KeyError as e:
        raise ValueError(f"unknown waf_type: {waf_type!r}") from e
    return template.format(src=src).strip()


_detect_cache: dict[tuple[str, float], str] = {}


def detect_waf_type(source: Path | list[Path]) -> str:
    """Which WAF produced a merged dataset, from its first record. Cached by (path, mtime).

    Detection is by field shape rather than the storage namespace, so the projection is always
    correct even if a file lands in the wrong place: Application Gateway records carry
    ``clientIp`` / ``transactionId`` / ``ruleSetType``; Front Door carries ``clientIP`` /
    ``trackingReference`` / ``ruleName``. An empty or unreadable file defaults to Front Door
    (its queries then just return nothing).
    """
    path = source if isinstance(source, Path) else source[0]
    try:
        key = (str(path), path.stat().st_mtime)
    except OSError:
        return FRONT_DOOR
    cached = _detect_cache.get(key)
    if cached is not None:
        return cached
    waf_type = _detect(path)
    _detect_cache[key] = waf_type
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
