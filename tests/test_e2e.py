"""Full offline pipeline over the seeded example dataset, exercised through HTTP."""

import json

DS = "frontdoor:2026-06-24"
DATE = "2026-06-24"  # the UTC day (download/stream take a date, not a dataset id)
DS23 = "frontdoor:2026-06-23"


def test_healthz(client):
    r = client.get("/api/healthz")
    assert r.status_code == 200 and r.json()["offline"] is True


def test_foreign_host_header_rejected(client):
    """DNS rebinding is the attack the host allowlist exists for: a page the operator visits can
    point its own hostname at 127.0.0.1 and issue simple requests here (CORS hides the response
    but doesn't stop the request). The browser sends the attacker's name in Host, so it fails."""
    r = client.get("/api/datasets", headers={"Host": "evil.example"})
    assert r.status_code == 400


def test_local_host_headers_accepted(client):
    for host in ("localhost:8000", "127.0.0.1:8000", "api:8000"):  # api = the Vite dev proxy
        assert client.get("/api/healthz", headers={"Host": host}).status_code == 200


def test_offline_download_refused(client):
    r = client.post("/api/datasets", json={"date": "2026-01-01"})
    assert r.status_code == 409


def test_create_dataset_surfaces_az_error_as_502(client, monkeypatch):
    """A download az failure returns an actionable 502, not a generic 500."""
    from lawless_waf.azure.discovery import AzureCliError

    def boom(*a, **k):
        raise AzureCliError("Azure denied blob access — try `az logout && az login`, then retry.")

    monkeypatch.setattr("lawless_waf.api.datasets.service.ensure_dataset", boom)
    r = client.post("/api/datasets", json={"date": "2026-01-01"})
    assert r.status_code == 502
    assert "az logout" in r.json()["detail"]


def test_stream_cached_dataset(client):
    """SSE download stream: a cached day completes immediately with a 'cached' event."""
    r = client.get(f"/api/datasets/stream?date={DATE}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    frames = [json.loads(line[5:]) for line in r.text.splitlines() if line.startswith("data:")]
    assert frames[-1]["phase"] == "cached"
    assert frames[-1]["dataset"]["dataset_id"] == DS


def test_stream_offline_emits_error_event(client):
    """A non-cached day under OFFLINE streams an 'error' event (not an HTTP error mid-stream)."""
    r = client.get("/api/datasets/stream?date=2026-01-01")
    assert r.status_code == 200
    frames = [json.loads(line[5:]) for line in r.text.splitlines() if line.startswith("data:")]
    assert frames == [{"phase": "error", "detail": frames[0]["detail"]}]
    assert "OFFLINE" in frames[0]["detail"]


def test_list_datasets(client):
    r = client.get("/api/datasets")
    assert r.status_code == 200
    ids = [d["dataset_id"] for d in r.json()["datasets"]]
    assert DS in ids


def test_scanner_report(client):
    r = client.get(f"/api/datasets/{DS}/scanner-report")
    body = r.json()
    assert r.status_code == 200
    assert body["scanner_ips"] == ["203.0.113.7"]
    assert body["genuine_fp_candidate_blocks"] == 3


def test_summary_overview(client):
    r = client.get(f"/api/datasets/{DS}/summary")
    assert r.status_code == 200
    body = r.json()
    assert set(body["actions"]) <= {"Block", "AnomalyScoring", "Log"}
    assert body["actions"]["Block"] > 0
    assert body["distinct_client_ips"] >= 1
    assert body["distinct_rules"] >= 1
    assert len(body["top_hosts"]) >= 1
    assert len(body["top_ips"]) >= 1
    assert len(body["timeline"]) >= 1
    assert {"bucket", "block", "anomaly", "log"} <= body["timeline"][0].keys()
    # policy mode/name context (explains the action mix to humans and the AI)
    assert {m["mode"] for m in body["policy_modes"]} == {"Prevention"}
    assert {p["policy"] for p in body["policies"]} == {"SampleWafPolicy"}


def test_exclusion_context_pipeline(client):
    r = client.get(f"/api/datasets/{DS}/rules/942100/exclusion-context")
    assert r.status_code == 200
    by_mv = {c["match_variable_name"]: c for c in r.json()["contexts"]}
    fp = by_mv["CookieValue:sessionId"]
    assert fp["classification"] == "false_positive"
    assert fp["terraform"]["selector"] == "sessionId"


def test_rule_events_row_level_drill(client):
    r = client.get(f"/api/datasets/{DS}/rules/942100/events?limit=10")
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) > 0
    e = events[0]
    # row-level fields needed to identify a false positive (incl. the rule message + mode context)
    assert {
        "client_ip", "host", "request_uri", "match_variable_name", "match_value", "msg", "policy_mode",
    } <= e.keys()


def test_rule_events_match_variable_filter(client):
    r = client.get(f"/api/datasets/{DS}/rules/942100/events?match_variable=CookieValue:sessionId&limit=10")
    assert r.status_code == 200
    names = {e["match_variable_name"] for e in r.json()["events"]}
    assert names == {"CookieValue:sessionId"}


def test_rule_events_limit_validated(client):
    assert client.get(f"/api/datasets/{DS}/rules/942100/events?limit=0").status_code == 422


def test_search_events(client):
    r = client.get(f"/api/datasets/{DS}/search?q=account&limit=10")
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) > 0
    e = events[0]
    assert {"client_ip", "host", "request_uri", "action", "rule_id", "policy_mode", "msg"} <= e.keys()
    assert all("account" in ev["request_uri"] for ev in events)


def test_search_requires_query(client):
    assert client.get(f"/api/datasets/{DS}/search").status_code == 422


def test_search_rejects_overlong_query(client):
    assert client.get(f"/api/datasets/{DS}/search?q={'x' * 201}").status_code == 422


def test_request_detail(client):
    r = client.get(f"/api/datasets/{DS}/requests/fp-0")
    assert r.status_code == 200
    body = r.json()
    assert body["anomaly_score"] == 8
    assert {row["action"] for row in body["rows"]} >= {"Block", "AnomalyScoring"}


def test_request_detail_invalid_ref_422(client):
    assert client.get(f"/api/datasets/{DS}/requests/bad ref!").status_code == 422


def test_policies_listed(client):
    r = client.get(f"/api/datasets/{DS}/policies")
    assert r.status_code == 200
    assert "SampleWafPolicy" in r.json()["policies"]


def test_policy_filter_scopes_rows(client):
    full = client.get(f"/api/datasets/{DS}/summary?policy=SampleWafPolicy").json()
    assert full["actions"]["Block"] > 0
    none = client.get(f"/api/datasets/{DS}/summary?policy=NoSuchPolicy").json()
    assert none["actions"] == {} and none["distinct_client_ips"] == 0


def test_multi_day_scope_param(client):
    one = client.get(f"/api/datasets/{DS}/summary").json()
    two = client.get(f"/api/datasets/{DS}/summary?dataset=frontdoor:2026-06-23").json()
    assert two["actions"]["Block"] == one["actions"]["Block"] * 2
    assert two["dataset_ids"] == [DS, DS23]


def test_diff_firing(client):
    r = client.get(f"/api/datasets/{DS}/diff?against=frontdoor:2026-06-23")
    assert r.status_code == 200
    rules = r.json()["rules"]
    assert rules and all(row["delta"] == 0 and row["status"] == "unchanged" for row in rules)


def test_rule_diff(client):
    r = client.get(f"/api/datasets/{DS}/rules/942100/diff?against=frontdoor:2026-06-23")
    assert r.status_code == 200
    body = r.json()
    assert body["before_hits"] == body["after_hits"] and body["resolved"] is False


def test_diff_against_unknown_404(client):
    assert client.get(f"/api/datasets/{DS}/diff?against=frontdoor:2099-01-01").status_code == 404


def test_exclusion_coverage(client):
    empty = client.post(f"/api/datasets/{DS}/exclusions/coverage", json={"tf_content": ""})
    assert empty.status_code == 200
    body = empty.json()
    assert body["total_exclusions"] == 0 and body["remaining"] == 100
    uncovered = {(c["rule_id"], c["match_variable_name"]) for c in body["uncovered_candidates"]}
    assert ("942100", "CookieValue:sessionId") in uncovered

    tf = 'exclusion { match_variable = "RequestCookieNames" operator = "Equals" selector = "sessionId" }'
    covered = client.post(f"/api/datasets/{DS}/exclusions/coverage", json={"tf_content": tf}).json()
    assert covered["total_exclusions"] == 1
    still = {(c["rule_id"], c["match_variable_name"]) for c in covered["uncovered_candidates"]}
    assert ("942100", "CookieValue:sessionId") not in still
    rows = {(c["rule_id"], c["match_variable_name"]): c for c in covered["coverage"]}
    assert rows[("942100", "CookieValue:sessionId")]["covered_by"]["selector"] == "sessionId"


def test_unknown_dataset_404(client):
    r = client.get("/api/datasets/frontdoor:2099-01-01/scanner-report")
    assert r.status_code == 404


def test_invalid_rule_id_rejected(client):
    # dashes/symbols are not valid rule ids (alphanumeric like 942100 or Bot300200 are)
    r = client.get(f"/api/datasets/{DS}/rules/no-such-rule/exclusion-context")
    assert r.status_code == 422


def test_alphanumeric_rule_id_accepted(client):
    # a BotManager-style id must validate (regression: used to 422 and break Investigate)
    r = client.get(f"/api/datasets/{DS}/rules/Bot300200/exclusion-context")
    assert r.status_code == 200


def test_exclusions_count(client):
    tf = '{ match_variable = "QueryStringArgNames" operator = "Equals" selector = "returnUrl" }'
    r = client.post("/api/exclusions/count", json={"tf_content": tf})
    assert r.status_code == 200
    assert r.json() == {
        "count": 1, "limit": 100, "remaining": 99,
        "by_match_variable": {"QueryStringArgNames": 1}, "consolidation_hints": [],
    }


# --- Application Gateway: the same pipeline over the AppGw-schema dataset the fixture seeds ---

APPGW = "appgw:2026-06-24"


def test_appgw_dataset_listed_with_type(client):
    ds = {d["dataset_id"]: d for d in client.get("/api/datasets").json()["datasets"]}
    assert APPGW in ds and ds[APPGW]["waf_type"] == "appgw"
    assert ds[DS]["waf_type"] == "frontdoor"


def test_appgw_scanner_report(client):
    body = client.get(f"/api/datasets/{APPGW}/scanner-report").json()
    assert body["scanner_ips"] == ["203.0.113.7"]  # same scanner IP as the FD sample
    assert body["genuine_fp_candidate_blocks"] == 3


def test_appgw_summary_normalizes_actions_and_modes(client):
    body = client.get(f"/api/datasets/{APPGW}/summary").json()
    # AppGw's Blocked/Matched/Detected are normalized to the canonical vocabulary.
    assert set(body["actions"]) <= {"Block", "AnomalyScoring", "Log"}
    assert body["actions"]["Block"] > 0 and body["actions"]["AnomalyScoring"] > 0
    modes = {m["mode"] for m in body["policy_modes"]}
    assert "Prevention" in modes and "Detection" in modes  # Detected rows -> Detection
    assert "SampleAppGwPolicy" in {p["policy"] for p in body["policies"]}  # last segment of policyId


def test_appgw_exclusion_context_maps_crs_collection(client):
    r = client.get(f"/api/datasets/{APPGW}/rules/942100/exclusion-context")
    assert r.status_code == 200
    by_mv = {c["match_variable_name"]: c for c in r.json()["contexts"]}
    # CRS "REQUEST_COOKIES:sessionId" -> the Application Gateway exclusion vocabulary.
    fp = by_mv["REQUEST_COOKIES:sessionId"]
    assert fp["classification"] == "false_positive"
    assert fp["terraform"] == {"match_variable": "RequestCookieNames", "selector": "sessionId"}
    # A body match has no arg/header/cookie selector -> not excludable.
    assert by_mv["REQUEST_BODY"]["classification"] == "not_excludable"
    assert by_mv["REQUEST_BODY"]["terraform"] is None


def test_appgw_request_detail_and_anomaly_score(client):
    body = client.get(f"/api/datasets/{APPGW}/requests/tx-fp-0").json()
    assert body["anomaly_score"] == 8
    assert {row["action"] for row in body["rows"]} >= {"Block", "AnomalyScoring"}


def test_appgw_coverage_uses_appgw_selector_match_operator(client):
    # An Application Gateway exclusion uses selector_match_operator (not operator).
    tf = 'exclusion { match_variable = "RequestCookieNames" selector_match_operator = "Equals" selector = "sessionId" }'
    covered = client.post(f"/api/datasets/{APPGW}/exclusions/coverage", json={"tf_content": tf}).json()
    assert covered["total_exclusions"] == 1
    still = {(c["rule_id"], c["match_variable_name"]) for c in covered["uncovered_candidates"]}
    assert ("942100", "REQUEST_COOKIES:sessionId") not in still


def test_mixing_waf_types_in_one_scope_is_rejected(client):
    r = client.get(f"/api/datasets/{DS}/summary?dataset={APPGW}")
    assert r.status_code == 422
    assert "mix WAF types" in r.json()["detail"]
