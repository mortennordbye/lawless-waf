import json

import pytest

from lawless_waf.duck import queries as q
from lawless_waf.sample import BLOCK_RULE, SCANNER_IP, SCORE_MSG, _rec, records

SQLI = "942100"
SQLI_RULE = "Microsoft_DefaultRuleSet-2.1-SQLI-942100"


@pytest.fixture(scope="module")
def null_ip_path(tmp_path_factory):
    """The sample plus one request whose clientIP is missing (Azure omits it occasionally)."""
    recs = records()
    uri = "https://app.example.com/nullip"
    recs.append(_rec(None, uri, "Block", BLOCK_RULE, "null-0", msg=SCORE_MSG))
    recs.append(
        _rec(None, uri, "AnomalyScoring", SQLI_RULE, "null-0",
             "CookieValue:sessionId", "123e4567-e89b-12d3-a456-426614174000", "SQL Injection")
    )
    p = tmp_path_factory.mktemp("nullip") / "merged.json"
    p.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    return p


def test_action_totals(sample_path):
    totals = {}
    for r in q.firing_rules(sample_path):
        totals[r["action"]] = totals.get(r["action"], 0) + r["total"]
    assert totals == {"AnomalyScoring": 23, "Block": 23, "Log": 2}


def test_rule_parsing(sample_path):
    rows = {r["rule_id"]: r["rule_group"] for r in q.firing_rules(sample_path)}
    assert rows["942100"] == "SQLI"
    assert rows["941100"] == "XSS"
    assert rows["930100"] == "LFI"


def test_top_block_cause(sample_path):
    rows = q.blocks_by_cause(sample_path)
    top = rows[0]
    assert top["rule_id"] == SQLI  # 7 scanner + 2 FP + 1 not-excludable
    assert top["hits"] == 10


def test_blocks_excluding_scanner(sample_path):
    rows = q.blocks_by_cause(sample_path, exclude_ips=[SCANNER_IP])
    by_id = {r["rule_id"]: r for r in rows}
    assert list(by_id) == [SQLI]  # scanner-only rules drop out
    assert by_id[SQLI]["hits"] == 3
    assert by_id[SQLI]["distinct_ips"] == 2


def test_rule_drill_unnest(sample_path):
    drill = q.rule_drill(sample_path, SQLI, exclude_ips=[SCANNER_IP])
    by_mv = {d["match_variable_name"]: d for d in drill}
    assert by_mv["CookieValue:sessionId"]["hits"] == 2
    assert "InitialBodyContents" in by_mv  # non-excludable still surfaces in the drill


def test_search_by_uri_substring(sample_path):
    rows = q.search_events(sample_path, "account")
    assert len(rows) > 0
    assert all("account" in r["request_uri"] for r in rows)


def test_search_by_ip_substring(sample_path):
    rows = q.search_events(sample_path, SCANNER_IP)
    assert len(rows) > 0
    assert all(r["client_ip"] == SCANNER_IP for r in rows)


def test_search_respects_limit(sample_path):
    rows = q.search_events(sample_path, "example.com", limit=3)
    assert len(rows) == 3


def test_search_no_match(sample_path):
    assert q.search_events(sample_path, "no-such-thing-xyz") == []


def test_action_events_filters_by_action(sample_path):
    blocks = q.action_events(sample_path, "Block")
    assert len(blocks) == 23
    assert all(r["action"] == "Block" for r in blocks)


def test_action_events_all_actions(sample_path):
    rows = q.action_events(sample_path)  # action=None → every firing action
    assert {r["action"] for r in rows} == {"Block", "AnomalyScoring", "Log"}
    assert len(rows) == 48  # 23 + 23 + 2


def test_action_events_respects_limit(sample_path):
    assert len(q.action_events(sample_path, "Block", limit=5)) == 5


def test_multi_source_sums_days(sample_path):
    one = q.summary(sample_path)
    two = q.summary([sample_path, sample_path])
    assert two["actions"]["Block"] == one["actions"]["Block"] * 2


def test_policy_filter(sample_path):
    assert q.summary(sample_path, policy="SampleWafPolicy")["actions"]["Block"] == 23
    assert q.summary(sample_path, policy="NoSuchPolicy")["actions"] == {}


def test_distinct_policies(sample_path):
    assert q.distinct_policies(sample_path) == ["SampleWafPolicy"]


def test_request_detail_rows(sample_path):
    rows = q.request_detail(sample_path, "fp-0")
    assert {r["action"] for r in rows} == {"Block", "AnomalyScoring"}
    scored = next(r for r in rows if r["action"] == "AnomalyScoring")
    assert scored["match_variable_names"] == ["CookieValue:sessionId"]


def test_null_client_ip_survives_the_exclude_filter(null_ip_path):
    """`NOT list_contains(list, NULL)` is NULL, i.e. falsy — a row with no clientIP would
    silently vanish from these three queries even with an empty exclude list, making their
    counts disagree with summary."""
    for exclude in ([], [SCANNER_IP]):
        by_id = {r["rule_id"]: r for r in q.blocks_by_cause(null_ip_path, exclude_ips=exclude)}
        # 2 FP + 1 not-excludable + 1 null-IP (+ 7 scanner when not excluded).
        assert by_id[SQLI]["hits"] == (11 if not exclude else 4)

        drill = q.rule_drill(null_ip_path, SQLI, exclude_ips=exclude)
        by_mv = {d["match_variable_name"]: d for d in drill}
        assert by_mv["CookieValue:sessionId"]["hits"] == 3  # 2 FP + the null-IP request

        events = q.rule_events(null_ip_path, SQLI, exclude_ips=exclude)
        assert any(e["client_ip"] is None for e in events)


def test_block_events_scanner_dominates(sample_path):
    events = q.block_events(sample_path)
    assert len(events) == 23
    counts = {}
    for e in events:
        counts[e["ip"]] = counts.get(e["ip"], 0) + 1
    assert counts[SCANNER_IP] == 20
