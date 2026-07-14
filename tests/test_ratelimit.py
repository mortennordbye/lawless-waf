"""Rate limiting is enforced on the analysis/query endpoints."""

import pytest
from fastapi.testclient import TestClient

import lawless_waf.settings as st
from lawless_waf.ratelimit import limiter
from lawless_waf.sample import write_sample


@pytest.fixture
def limited_client(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    write_sample(data_dir / "2026-06-24" / "merged.json")

    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("OFFLINE", "true")
    monkeypatch.setenv("QUERY_RATE_LIMIT", "2/minute")
    st._settings = None
    limiter.enabled = True
    limiter.reset()

    from lawless_waf.main import create_app

    yield TestClient(create_app(), base_url="http://localhost")  # default Host fails the allowlist

    st._settings = None
    limiter.enabled = False
    limiter.reset()


def test_query_rate_limit_429(limited_client):
    assert limited_client.get("/api/datasets").status_code == 200
    assert limited_client.get("/api/datasets").status_code == 200
    assert limited_client.get("/api/datasets").status_code == 429
