"""MCP server tools over the seeded sample dataset (the tool functions are called directly)."""

import pytest

import lawless_waf.settings as st
from lawless_waf import mcp_server as m
from lawless_waf.models import MAX_TF_CONTENT
from lawless_waf.sample import write_sample


@pytest.fixture
def mcp_data(tmp_path, monkeypatch):
    """Point the MCP server at a data dir holding the sample datasets (Front Door + AppGw)."""
    data_dir = tmp_path / "data"
    write_sample(data_dir / "frontdoor" / "2026-06-24" / "merged.json")
    write_sample(data_dir / "appgw" / "2026-06-24" / "merged.json", waf_type="appgw")
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("OFFLINE", "true")
    st._settings = None
    yield "frontdoor:2026-06-24"
    st._settings = None


def test_list_and_scope_tools_return_data(mcp_data):
    ds = mcp_data
    assert ds in [d["dataset_id"] for d in m.list_datasets()["datasets"]]

    actions = m.summary(ds)["actions"]
    assert actions["Block"] == 23  # same numbers the REST/query tests assert

    blocks = m.events_by_action(ds, action="Block")["events"]
    assert blocks and all(e["action"] == "Block" for e in blocks)

    ctx = m.exclusion_context(ds, "942100")
    by_mv = {c["match_variable_name"]: c for c in ctx["contexts"]}
    assert by_mv["CookieValue:sessionId"]["classification"] == "false_positive"


def test_unknown_dataset_is_a_clear_error(mcp_data):
    with pytest.raises(ValueError, match="not found"):
        m.summary("frontdoor:2099-01-01")


def test_inputs_are_validated_at_the_mcp_boundary(mcp_data):
    ds = mcp_data
    # MCP bypasses FastAPI query validation, so the server must reject hostile input itself.
    with pytest.raises(ValueError, match="policy"):
        m.summary(ds, policy="bad'; DROP")
    with pytest.raises(ValueError, match="rule_id"):
        m.exclusion_context(ds, "not a rule id!")
    # The REST models cap a pasted .tf; this boundary has no pydantic model to do it.
    huge = "x" * (MAX_TF_CONTENT + 1)
    with pytest.raises(ValueError, match="too large"):
        m.exclusions_count(huge)
    with pytest.raises(ValueError, match="too large"):
        m.coverage(ds, huge)


def test_search_narrows_to_one_action(mcp_data):
    ds = mcp_data
    every = m.search(ds, "example.com", limit=500)["events"]
    assert len({e["action"] for e in every}) > 1  # unfiltered, the drill spans actions

    blocked = m.search(ds, "example.com", limit=500, action="Block")["events"]
    assert blocked and all(e["action"] == "Block" for e in blocked)
    assert len(blocked) < len(every)

    with pytest.raises(ValueError, match="action"):
        m.search(ds, "example.com", action="Nope")


def test_exclusions_count_reports_slots_and_consolidation_hints(mcp_data):
    tf = """
    exclusion { match_variable = "RequestCookieNames" operator = "Equals" selector = "sessionId" }
    exclusion { match_variable = "RequestCookieNames" operator = "Equals" selector = "sessionToken" }
    """
    out = m.exclusions_count(tf)
    assert out["count"] == 2 and out["remaining"] == 98
    assert out["by_match_variable"] == {"RequestCookieNames": 2}
    # Both selectors share the "session" prefix, so they could collapse into one StartsWith slot.
    assert out["consolidation_hints"][0]["slots_saved"] == 1


def test_refresh_live_offline_refuses(mcp_data):
    # OFFLINE=true: refresh must refuse rather than attempt an Azure pull.
    with pytest.raises(Exception, match="OFFLINE"):
        m.refresh_live("2026-06-25", 12)


def test_appgw_dataset_analyzes_through_mcp(mcp_data):
    """The MCP tools work over an Application Gateway dataset too (same service layer)."""
    ds = "appgw:2026-06-24"
    assert ds in [d["dataset_id"] for d in m.list_datasets()["datasets"]]
    assert m.scanner_report(ds)["scanner_ips"] == ["203.0.113.7"]
    ctx = m.exclusion_context(ds, "942100")
    by_mv = {c["match_variable_name"]: c for c in ctx["contexts"]}
    assert by_mv["REQUEST_COOKIES:sessionId"]["terraform"] == {
        "match_variable": "RequestCookieNames", "selector": "sessionId"
    }
