"""MCP server tools over the seeded sample dataset (the tool functions are called directly)."""

import pytest

import lawless_waf.settings as st
from lawless_waf import mcp_server as m
from lawless_waf.sample import write_sample


@pytest.fixture
def mcp_data(tmp_path, monkeypatch):
    """Point the MCP server at a data dir holding the sample dataset (id 2026-06-24)."""
    data_dir = tmp_path / "data"
    write_sample(data_dir / "2026-06-24" / "merged.json")
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("OFFLINE", "true")
    st._settings = None
    yield "2026-06-24"
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
        m.summary("2099-01-01")


def test_inputs_are_validated_at_the_mcp_boundary(mcp_data):
    ds = mcp_data
    # MCP bypasses FastAPI query validation, so the server must reject hostile input itself.
    with pytest.raises(ValueError, match="policy"):
        m.summary(ds, policy="bad'; DROP")
    with pytest.raises(ValueError, match="rule_id"):
        m.exclusion_context(ds, "not a rule id!")


def test_refresh_live_offline_refuses(mcp_data):
    # OFFLINE=true: refresh must refuse rather than attempt an Azure pull.
    with pytest.raises(Exception, match="OFFLINE"):
        m.refresh_live("2026-06-25", 12)
